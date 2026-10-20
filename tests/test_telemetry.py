import json
import pytest
from cybershield import database as db, telemetry
from cybershield.engine import process_event, manual_response
from cybershield.enforcement import NftablesProvider, SimulationProvider
from cybershield.threat_detector import score_event


def test_score_rule_boundaries():
    assert score_event({"event_type": "normal", "unique_ports": 19}).score == 0
    assert score_event({"event_type": "normal", "unique_ports": 20}).score == 35
    assert score_event({"event_type": "normal", "failed_attempts": 10}).score == 30
    assert score_event({"event_type": "normal", "connections_per_minute": 120}).score == 25


def test_event_persisted_and_exact_duplicate_suppressed(tmp_path):
    path = tmp_path / "db.sqlite"; db.init_db(path)
    event = {"src_ip": "192.0.2.1", "event_type": "normal", "evidence": "test"}
    first = process_event(event, db_path=path)
    second = process_event(event, db_path=path)
    assert first["event_id"] == second["event_id"]
    assert second["duplicate"] is True
    assert db.counts(path)["events"] == 1


def test_same_event_is_accepted_after_dedup_window(tmp_path):
    path = tmp_path / "db.sqlite"; db.init_db(path)
    event = {"src_ip": "192.0.2.2", "event_type": "normal", "evidence": "test"}
    process_event(event, db_path=path)
    with db.connect(path) as conn:
        conn.execute("UPDATE events SET timestamp='2020-01-01T00:00:00+00:00'")
    result = process_event(event, db_path=path)
    assert result["duplicate"] is False
    assert db.counts(path)["events"] == 2


def test_malformed_structured_input():
    with pytest.raises(ValueError): telemetry.parse_events(b'{bad', 'events.json')
    with pytest.raises(ValueError): telemetry.parse_events(b'{"events":[{}]}', 'events.json')


def test_csv_normalization():
    records = telemetry.parse_events(b'src_ip,dst_ip,dst_port,protocol\n192.0.2.1,198.51.100.2,443,TCP\n', 'events.csv')
    assert records[0]["dst_port"] == 443
    assert records[0]["source"] == "offline"


def test_pcap_parsing(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    from scapy.layers.inet import IP, TCP
    from scapy.utils import wrpcap
    path = tmp_path / "fixture.pcap"
    wrpcap(str(path), [IP(src="192.0.2.1", dst="198.51.100.2")/TCP(sport=1234, dport=443)])
    records = telemetry.parse_pcap(path.read_bytes())
    assert records[0]["src_ip"] == "192.0.2.1"
    assert records[0]["dst_port"] == 443
    assert records[0]["protocol"] == "TCP"


def test_failed_attempt_inference_is_not_made():
    record = telemetry.annotate_patterns([{"src_ip":"192.0.2.1", "dst_port":22, "event_type":"connection"}])[0]
    assert "failed_attempts" not in record


def test_port_scan_window_detection():
    records = [{"src_ip":"192.0.2.1", "dst_port":port, "timestamp":"2026-10-20T10:00:00+00:00"}
               for port in range(1, 4)]
    flagged = telemetry.annotate_patterns(records, window_seconds=60, scan_ports=3)
    assert all(r["event_type"] == "port_scan" for r in flagged)
    later = dict(records[0], timestamp="2026-10-20T10:05:00+00:00")
    separated = telemetry.annotate_patterns([*records[:2], later], window_seconds=60, scan_ports=3)
    assert all(r.get("event_type") != "port_scan" for r in separated)


def test_simulated_manual_response_audited(tmp_path):
    path = tmp_path / "db.sqlite"; db.init_db(path); db.add_device("192.0.2.1", "lab", db_path=path)
    result = manual_response("192.0.2.1", "quarantine", db_path=path)
    assert result["status"] == "simulated" and not result["verified"]
    assert db.get_response_actions(db_path=path)[0]["verified"] == 0
    assert db.get_audit_log(db_path=path)


def test_alert_triage_transitions_are_audited(tmp_path):
    path = tmp_path / "db.sqlite"; db.init_db(path)
    alert_id = db.create_alert("192.0.2.3", "high", "Test alert", "Evidence", 75, path)
    assert db.update_alert_status(alert_id, "acknowledged", db_path=path)
    assert db.get_alerts(db_path=path)[0]["status"] == "acknowledged"
    assert db.get_audit_log(db_path=path)[0]["action"] == "alert:open->acknowledged"


def test_unsafe_enforcement_targets_rejected():
    with pytest.raises(ValueError): NftablesProvider._target("127.0.0.1")
    with pytest.raises(ValueError): NftablesProvider._target("224.0.0.1")
    with pytest.raises(ValueError): NftablesProvider._target("2001:db8::1")


def test_nftables_provider_failure_is_reported_without_shell(monkeypatch):
    provider = NftablesProvider()
    monkeypatch.setattr(provider, "capabilities", lambda: {"available": True, "enforces": True})
    class Failed:
        returncode = 1; stdout = ""; stderr = "denied"
    monkeypatch.setattr(provider, "_run", lambda args: Failed())
    result = provider.quarantine("192.0.2.9")
    assert result.success is False
    assert result.verified is False
    assert result.status == "failed"
