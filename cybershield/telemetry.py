"""Offline network telemetry import. Live capture is opt-in and requires Scapy/OS permissions."""
import csv
import io
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

MAX_PACKETS = 250_000


def _normalize(row: dict[str, Any], source: str = "offline") -> dict[str, Any]:
    src = row.get("src_ip", row.get("source_ip", row.get("src", "")))
    dst = row.get("dst_ip", row.get("destination_ip", row.get("dst", "")))
    if not src:
        raise ValueError("Each network record must include src_ip/source_ip")
    proto = str(row.get("protocol", "unknown")).upper()
    try:
        sport = int(row["src_port"]) if row.get("src_port") not in (None, "") else None
        dport = int(row.get("dst_port", row.get("destination_port"))) if row.get("dst_port", row.get("destination_port")) not in (None, "") else None
    except (ValueError, TypeError):
        raise ValueError("Ports must be integers")
    stamp = row.get("timestamp") or datetime.now(timezone.utc).isoformat()
    return {"src_ip": str(src), "dst_ip": str(dst) if dst else None, "src_port": sport,
            "dst_port": dport, "protocol": proto, "timestamp": str(stamp),
            "event_type": str(row.get("event_type", "connection")), "source": source,
            "connection_outcome": row.get("connection_outcome"),
            "evidence": "Packet metadata observed; suspicious behavior is inferred by rules."}


def parse_events(data: bytes | str, filename: str) -> list[dict[str, Any]]:
    if len(data) > 20 * 1024 * 1024:
        raise ValueError("Upload exceeds 20 MiB limit")
    if isinstance(data, bytes):
        data = data.decode("utf-8-sig")
    suffix = filename.lower().rsplit(".", 1)[-1]
    try:
        if suffix == "json":
            raw = json.loads(data)
            rows = raw if isinstance(raw, list) else raw.get("events", [])
        elif suffix in {"csv", "tsv"}:
            rows = list(csv.DictReader(io.StringIO(data), delimiter="\t" if suffix == "tsv" else ","))
        else:
            raise ValueError("Supported offline event formats are JSON, CSV, and TSV")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed event file: {exc}") from exc
    if not isinstance(rows, list):
        raise ValueError("Event file must contain a list of records")
    if len(rows) > MAX_PACKETS:
        raise ValueError(f"File contains more than {MAX_PACKETS} records")
    return [_normalize(row) for row in rows if isinstance(row, dict)]


def parse_pcap(data: bytes, filename: str = "capture.pcap") -> list[dict[str, Any]]:
    try:
        from scapy.utils import rdpcap
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError("PCAP support requires Scapy. Install it with: pip install scapy") from exc
    if len(data) > 20 * 1024 * 1024:
        raise ValueError("Upload exceeds 20 MiB limit")
    packets = rdpcap(io.BytesIO(data), count=MAX_PACKETS + 1)
    if len(packets) > MAX_PACKETS:
        raise ValueError(f"PCAP exceeds {MAX_PACKETS} packet limit")
    rows = []
    for pkt in packets:
        layer = IP if IP in pkt else IPv6 if IPv6 in pkt else None
        if not layer:
            continue
        ip = pkt[layer]
        proto, sport, dport = "other", None, None
        if TCP in pkt:
            proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif UDP in pkt:
            proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
        rows.append(_normalize({"src_ip": ip.src, "dst_ip": ip.dst, "src_port": sport, "dst_port": dport,
                                "protocol": proto, "timestamp": datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat()}, "pcap"))
    return rows


def annotate_patterns(records: list[dict[str, Any]], window_seconds: int = 60, scan_ports: int = 20,
                      attempts: int = 30) -> list[dict[str, Any]]:
    """Annotate source behavior within an offline batch; no failed connections are inferred."""
    result = [dict(r) for r in records]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in result:
        grouped[r["src_ip"]].append(r)
    for source_rows in grouped.values():
        buckets: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for index, row in enumerate(source_rows):
            try:
                stamp = datetime.fromisoformat(str(row["timestamp"]).replace("Z", "+00:00")).timestamp()
                key = int(stamp // max(1, window_seconds))
            except (ValueError, TypeError, KeyError, OverflowError):
                key = 0
            buckets[key].append(row)
        for window_rows in buckets.values():
            ports = {r.get("dst_port") for r in window_rows if r.get("dst_port") is not None}
            if len(ports) >= scan_ports:
                for r in window_rows:
                    r.update(event_type="port_scan", unique_ports=len(ports),
                             explanation=f"Source contacted {len(ports)} destination ports in a {window_seconds}s window")
            elif len(window_rows) >= attempts:
                for r in window_rows:
                    r.update(event_type="repeated_connections", connections_per_minute=len(window_rows) * 60 // max(1, window_seconds),
                             explanation=f"{len(window_rows)} observed connection records in a {window_seconds}s window")
        # Passive captures cannot establish failed TCP handshakes without reliable outcome telemetry.
    return result


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except (ImportError, OSError):
        return []


def capture_live(interface: str, count: int = 100, timeout: int = 30) -> list[dict[str, Any]]:
    if not interface or interface not in list_interfaces():
        raise ValueError("Select a supported capture interface")
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Live capture requires Scapy. Install it with: pip install scapy") from exc
    try:
        packets = sniff(iface=interface, count=max(1, min(int(count), 1000)), timeout=max(1, min(int(timeout), 120)))
        from scapy.utils import wrpcap
        buf = io.BytesIO(); wrpcap(buf, packets)
        return parse_pcap(buf.getvalue(), "live.pcap")
    except PermissionError as exc:
        raise RuntimeError("Capture permission denied; dashboard remains usable without live capture") from exc
