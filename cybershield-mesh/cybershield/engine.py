from typing import Any
import json
import ipaddress
from datetime import datetime, timezone

from . import database as db
from .config import RISK_THRESHOLD
from .threat_detector import score_event
from .enforcement import get_provider
from .config import ENFORCEMENT_MODE


def process_event(event: dict[str, Any], threshold: int = RISK_THRESHOLD, db_path=None,
                  detection_thresholds: dict[str, int] | None = None) -> dict[str, Any]:
    required = ("src_ip", "event_type")
    if any(not str(event.get(k, "")).strip() for k in required):
        raise ValueError("Each event requires src_ip and event_type")
    src_ip = str(event["src_ip"]).strip()
    try:
        ipaddress.ip_address(src_ip)
    except ValueError as exc:
        raise ValueError("src_ip must be a valid IP address") from exc
    dst_ip = str(event.get("dst_ip", "") or "").strip() or None
    detection = score_event(event, detection_thresholds or event.get("detection_thresholds"))
    # Collapse exact repeated observations in a short window to avoid alert storms.
    for previous in db.get_events(100, db_path):
        if previous["src_ip"] != src_ip or previous["event_type"] != str(event["event_type"]):
            continue
        try:
            identical = json.loads(previous["details"]) == event
        except (TypeError, json.JSONDecodeError):
            identical = False
        try:
            seen_at = datetime.fromisoformat(previous["timestamp"].replace("Z", "+00:00"))
            age_seconds = (datetime.now(timezone.utc) - seen_at).total_seconds()
        except (ValueError, TypeError):
            age_seconds = 10**9
        if identical and 0 <= age_seconds <= 60:
            return {"event_id": previous["id"], "src_ip": src_ip, "score": previous["risk_score"],
                    "severity": detection.severity, "title": detection.title, "reasons": list(detection.reasons),
                    "action": "duplicate suppressed", "duplicate": True}
    devices = {d["ip"]: d for d in db.get_devices(db_path)}
    if src_ip not in devices:
        db.add_device(src_ip, f"Device {src_ip}", "Discovered device", db_path)
    db.update_device_risk(src_ip, detection.score, db_path)

    action = "observed"
    if detection.score >= threshold:
        db.create_alert(src_ip, detection.severity, detection.title,
                        "; ".join(detection.reasons), detection.score, db_path)
        provider = get_provider(ENFORCEMENT_MODE)
        result = provider.quarantine(src_ip)
        result_dict = {"success": result.success, "provider": result.provider, "status": result.status,
                       "verified": result.verified, "message": result.message}
        db.record_response(src_ip, "automatic_quarantine", result_dict, db_path)
        if result.success:
            db.set_device_status(src_ip, "quarantined", actor="auto-response",
                                 details=f"{result.status}: {result.message}", db_path=db_path)
            action = "quarantined (simulated)" if result.provider == "simulation" else "quarantined (enforced)"
        else:
            action = "enforcement failed"
    elif detection.suspicious:
        db.create_alert(src_ip, detection.severity, detection.title,
                        "; ".join(detection.reasons), detection.score, db_path)
        action = "alerted"

    event_id = db.record_event(src_ip, dst_ip, str(event["event_type"]), dict(event), detection.score, action, db_path)
    return {"event_id": event_id, "src_ip": src_ip, "score": detection.score,
            "severity": detection.severity, "title": detection.title,
            "reasons": list(detection.reasons), "action": action, "duplicate": False,
            "evidence": event.get("evidence", "Rule-based inference from supplied event metadata")}


def seed_lab(db_path=None) -> None:
    devices = [
        ("192.168.10.10", "Admin Workstation", "Workstation"),
        ("192.168.10.20", "Engineering Laptop", "Laptop"),
        ("192.168.10.30", "File Server", "Server"),
        ("192.168.10.40", "IoT Camera", "IoT"),
    ]
    for ip, name, kind in devices:
        db.add_device(ip, name, kind, db_path)


def manual_response(ip: str, operation: str, db_path=None, provider_mode: str = ENFORCEMENT_MODE) -> dict[str, Any]:
    """Apply response through selected provider and persist attempt before changing device state."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("Target must be a valid IP address") from exc
    provider = get_provider(provider_mode)
    result = provider.quarantine(ip) if operation == "quarantine" else provider.release(ip)
    payload = {"success": result.success, "provider": result.provider, "status": result.status,
               "verified": result.verified, "message": result.message}
    db.record_response(ip, f"manual_{operation}", payload, db_path)
    if result.success:
        db.set_device_status(ip, "quarantined" if operation == "quarantine" else "online",
                             actor="operator", details=f"{result.status}: {result.message}", db_path=db_path)
        if operation == "release": db.resolve_alerts_for_ip(ip, db_path)
    return payload


def simulate_normal(db_path=None, threshold: int = RISK_THRESHOLD) -> dict[str, Any]:
    return process_event({"src_ip": "192.168.10.20", "dst_ip": "192.168.10.30",
                          "event_type": "normal", "connections_per_minute": 12,
                          "unique_ports": 3, "failed_attempts": 0, "source": "demo"}, threshold=threshold, db_path=db_path)


def simulate_port_scan(db_path=None, threshold: int = RISK_THRESHOLD) -> dict[str, Any]:
    return process_event({"src_ip": "192.168.10.40", "dst_ip": "192.168.10.30",
                          "event_type": "port_scan", "connections_per_minute": 160,
                          "unique_ports": 48, "failed_attempts": 0, "source": "demo"}, threshold=threshold, db_path=db_path)


def simulate_brute_force(db_path=None, threshold: int = RISK_THRESHOLD) -> dict[str, Any]:
    return process_event({"src_ip": "192.168.10.40", "dst_ip": "192.168.10.30",
                          "event_type": "brute_force", "connections_per_minute": 35,
                          "unique_ports": 1, "failed_attempts": 24, "source": "demo"}, threshold=threshold, db_path=db_path)
