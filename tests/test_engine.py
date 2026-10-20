import pytest
from cybershield import database as db
from cybershield.engine import process_event, seed_lab
from cybershield.threat_detector import score_event


@pytest.fixture
def db_path(tmp_path):
    path = tmp_path / "test.db"
    db.init_db(path)
    seed_lab(path)
    return path


def test_normal_event_is_observed(db_path):
    result = process_event({"src_ip": "192.168.10.20", "event_type": "normal",
                            "unique_ports": 2, "failed_attempts": 0,
                            "connections_per_minute": 10}, db_path=db_path)
    assert result["score"] == 0
    assert result["action"] == "observed"
    assert db.counts(db_path)["open_alerts"] == 0


def test_port_scan_triggers_lab_quarantine(db_path):
    result = process_event({"src_ip": "192.168.10.40", "event_type": "port_scan",
                            "unique_ports": 45}, threshold=75, db_path=db_path)
    assert result["score"] >= 75
    assert "quarantined" in result["action"]
    device = next(d for d in db.get_devices(db_path) if d["ip"] == "192.168.10.40")
    assert device["status"] == "quarantined"
    assert db.counts(db_path)["open_alerts"] == 1


def test_medium_risk_creates_alert_without_quarantine(db_path):
    result = process_event({"src_ip": "192.168.10.20", "event_type": "brute_force"},
                           threshold=75, db_path=db_path)
    assert result["score"] == 65
    assert result["action"] == "alerted"
    device = next(d for d in db.get_devices(db_path) if d["ip"] == "192.168.10.20")
    assert device["status"] == "online"


def test_missing_source_ip_rejected(db_path):
    with pytest.raises(ValueError):
        process_event({"event_type": "normal"}, db_path=db_path)


def test_detector_caps_score_at_100():
    result = score_event({"event_type": "port_scan", "unique_ports": 100,
                          "failed_attempts": 500, "connections_per_minute": 5000})
    assert result.score == 100
    assert result.severity == "critical"


def test_manual_release_is_audited(db_path):
    db.set_device_status("192.168.10.40", "quarantined", actor="test", db_path=db_path)
    db.set_device_status("192.168.10.40", "online", actor="test", details="test release", db_path=db_path)
    device = next(d for d in db.get_devices(db_path) if d["ip"] == "192.168.10.40")
    assert device["status"] == "online"
    assert len(db.get_audit_log(db_path=db_path)) == 2
