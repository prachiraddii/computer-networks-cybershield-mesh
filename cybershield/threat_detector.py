from dataclasses import dataclass
from typing import Any
from .config import RISK_THRESHOLD


@dataclass(frozen=True)
class Detection:
    score: int
    severity: str
    title: str
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return self.score >= 40


def score_event(event: dict[str, Any], thresholds: dict[str, int] | None = None) -> Detection:
    """Transparent, explainable rules for lab events; not an ML classifier."""
    event_type = str(event.get("event_type", "normal")).lower()
    score = 0
    reasons: list[str] = []
    title = "Normal network activity"

    rules = {"port_scan_ports": 20, "failed_attempts": 10, "connections_per_minute": 120}
    rules.update(thresholds or {})
    if event_type in {"port_scan", "port scan"}:
        score += 85
        title = "Possible port scan detected"
        reasons.append("One source contacted many destination ports in a short interval")
    if event_type in {"brute_force", "brute-force", "failed_logins"}:
        score += 65
        title = "Repeated authentication failures"
        reasons.append("Repeated failed authentication attempts were reported")
    if event_type in {"traffic_spike", "flood"}:
        score += 70
        title = "Unusual traffic volume"
        reasons.append("Connection rate exceeded the lab threshold")

    unique_ports = int(event.get("unique_ports", 0) or 0)
    failed_attempts = int(event.get("failed_attempts", 0) or 0)
    connections_per_minute = int(event.get("connections_per_minute", 0) or 0)
    if unique_ports >= rules["port_scan_ports"] and event_type not in {"port_scan", "port scan"}:
        score += 35
        reasons.append(f"High port diversity ({unique_ports} unique ports)")
    if failed_attempts >= rules["failed_attempts"] and event_type not in {"brute_force", "brute-force", "failed_logins"}:
        score += 30
        reasons.append(f"Many failed attempts ({failed_attempts})")
    if connections_per_minute >= rules["connections_per_minute"] and event_type not in {"traffic_spike", "flood"}:
        score += 25
        reasons.append(f"High connection rate ({connections_per_minute}/min)")

    score = min(score, 100)
    if not reasons:
        reasons.append("No configured suspicious behavior pattern matched")
    severity = "critical" if score >= 85 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    if score == 0:
        title = "Normal network activity"
    return Detection(score, severity, title, tuple(reasons))
