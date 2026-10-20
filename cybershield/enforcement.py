"""Provider-based isolation. Simulation is default; nftables is explicit lab-only."""
from dataclasses import dataclass
import ipaddress
import platform
import shutil
import socket
import subprocess

@dataclass
class EnforcementResult:
    success: bool
    provider: str
    status: str
    verified: bool
    message: str

class SimulationProvider:
    name = "simulation"
    def capabilities(self): return {"available": True, "enforces": False, "description": "Records a simulated decision only"}
    def quarantine(self, ip): return EnforcementResult(True, self.name, "simulated", False, "No network traffic was blocked")
    def release(self, ip): return EnforcementResult(True, self.name, "simulated_release", False, "No network rule required removal")

class NftablesProvider:
    name = "nftables"
    table = "cybershield_lab"
    chain = "quarantine"
    def capabilities(self):
        available = platform.system() == "Linux" and shutil.which("nft") is not None
        return {"available": available, "enforces": available, "description": "Linux nftables IPv4 input filter (isolated lab only)"}
    @staticmethod
    def _target(ip):
        value = ipaddress.ip_address(ip)
        if value.version != 4 or value.is_loopback or value.is_unspecified or value.is_multicast or value.is_link_local:
            raise ValueError("Unsafe enforcement target; only unicast IPv4 lab endpoints are allowed")
        try:
            local = {item[4][0] for item in socket.getaddrinfo(socket.gethostname(), None)
                     if item[0] == socket.AF_INET}
        except OSError:
            local = set()
        if str(value) in local:
            raise ValueError("Refusing to isolate this management host address")
        return str(value)
    def _run(self, args):
        return subprocess.run(["nft", *args], capture_output=True, text=True, timeout=5, check=False)
    def quarantine(self, ip):
        ip = self._target(ip)
        if not self.capabilities()["available"]: return EnforcementResult(False, self.name, "unsupported", False, "nftables is unavailable")
        # Never create/flush global policy; named owned table makes cleanup bounded.
        if self._run(["list", "table", "inet", self.table]).returncode != 0:
            for args in (["add", "table", "inet", self.table], ["add", "chain", "inet", self.table, self.chain, "{", "type", "filter", "hook", "input", "priority", "-5", ";", "policy", "accept", ";", "}"]):
                if self._run(args).returncode != 0: return EnforcementResult(False, self.name, "failed", False, "Could not create isolated CyberShield nftables chain")
        existing = self._run(["list", "chain", "inet", self.table, self.chain]).stdout
        if ip in existing: return EnforcementResult(True, self.name, "enforced", True, "Existing CyberShield rule verified")
        added = self._run(["add", "rule", "inet", self.table, self.chain, "ip", "saddr", ip, "drop", "comment", "cybershield-managed"])
        verified = self._run(["list", "chain", "inet", self.table, self.chain])
        ok = added.returncode == 0 and verified.returncode == 0 and ip in verified.stdout
        return EnforcementResult(ok, self.name, "enforced" if ok else "verification_failed", ok, "Rule applied and verified" if ok else "Rule application or verification failed")
    def release(self, ip):
        ip = self._target(ip)
        if not self.capabilities()["available"]: return EnforcementResult(False, self.name, "unsupported", False, "nftables is unavailable")
        listed = self._run(["-a", "list", "chain", "inet", self.table, self.chain])
        if listed.returncode != 0: return EnforcementResult(True, self.name, "released", True, "No CyberShield table exists")
        for line in listed.stdout.splitlines():
            if ip in line and "cybershield-managed" in line:
                handle = line.rsplit("handle ", 1)[-1].strip()
                if handle.isdigit(): self._run(["delete", "rule", "inet", self.table, self.chain, "handle", handle])
        remaining = self._run(["list", "chain", "inet", self.table, self.chain]).stdout
        ok = ip not in remaining
        return EnforcementResult(ok, self.name, "released" if ok else "verification_failed", ok, "Owned rule removed" if ok else "Could not verify removal")

def get_provider(mode="simulation"):
    if mode == "nftables": return NftablesProvider()
    return SimulationProvider()
