import json
import os
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cybershield import database as db
from cybershield.config import APP_NAME, RISK_THRESHOLD, MAX_UPLOAD_BYTES, ENFORCEMENT_MODE, LIVE_CAPTURE_ENABLED, DETECTION_THRESHOLDS, DETECTION_WINDOW_SECONDS
from cybershield.engine import seed_lab, simulate_brute_force, simulate_normal, simulate_port_scan, process_event, manual_response
from cybershield import telemetry
from cybershield.enforcement import get_provider

st.set_page_config(page_title=APP_NAME, page_icon="🛡️", layout="wide")
db.init_db()

st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
div[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.22); padding: 14px; border-radius: 12px;}
.small-muted {color: #808080; font-size: .9rem;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CyberShield Mesh")
st.caption("Explainable network threat detection · Lab quarantine · Event and audit history")
provider = get_provider(ENFORCEMENT_MODE)
caps = provider.capabilities()
st.warning("SIMULATED QUARANTINE: decisions are recorded in CyberShield only; no traffic is blocked." if not caps["enforces"] else
           "ENFORCEMENT MODE ENABLED: Linux nftables may block selected IPv4 traffic. Use only an isolated lab.", icon="⚠️")

with st.sidebar:
    st.header("Control Center")
    st.caption(f"Provider: {provider.name} · Available: {caps['available']} · Enforces traffic: {caps['enforces']}")
    threshold = st.slider("Auto-quarantine risk threshold", min_value=40, max_value=100,
                          value=max(40, min(100, RISK_THRESHOLD)), step=5,
                          help="Events at or above this score trigger lab-state quarantine.")
    st.subheader("Detection thresholds")
    rule_thresholds = {
        "port_scan_ports": st.number_input("Distinct destination ports", min_value=2, max_value=65535, value=DETECTION_THRESHOLDS["port_scan_ports"]),
        "failed_attempts": st.number_input("Reported failed attempts", min_value=1, max_value=100000, value=DETECTION_THRESHOLDS["failed_attempts"]),
        "connections_per_minute": st.number_input("Connections per minute", min_value=1, max_value=1000000, value=DETECTION_THRESHOLDS["connections_per_minute"]),
    }
    detection_window = st.number_input("Detection window (seconds)", min_value=5, max_value=3600,
                                       value=DETECTION_WINDOW_SECONDS)
    if st.button("Initialize / refresh lab devices", use_container_width=True):
        seed_lab()
        st.success("Lab devices initialized.")
        st.rerun()
    st.divider()
    st.subheader("Demo scenarios")
    if st.button("▶ Normal traffic", use_container_width=True):
        result = simulate_normal(threshold=threshold)
        st.session_state["last_result"] = result
        st.rerun()
    if st.button("⚠ Simulate port scan", use_container_width=True):
        result = simulate_port_scan(threshold=threshold)
        st.session_state["last_result"] = result
        st.rerun()
    if st.button("⚠ Simulate brute-force activity", use_container_width=True):
        result = simulate_brute_force(threshold=threshold)
        st.session_state["last_result"] = result
        st.rerun()
    st.divider()
    if st.button("Reset all lab data", type="secondary", use_container_width=True):
        db.clear_demo_data()
        seed_lab()
        st.session_state.pop("last_result", None)
        st.success("Lab data reset.")
        st.rerun()

# Make the first launch useful without requiring a button.
if not db.get_devices():
    seed_lab()

if "last_result" in st.session_state:
    r = st.session_state["last_result"]
    if r.get("duplicate"):
        st.info(f"Repeated event from {r['src_ip']} suppressed within the 60-second deduplication window · risk {r['score']}/100")
    else:
        st.success(f"Processed event from {r['src_ip']}: risk {r['score']}/100 · {r['action']}")
    st.caption("Reasoning: " + "; ".join(r["reasons"]))

counts = db.counts()
metrics = st.columns(5)
for col, label, value in zip(metrics,
    ["Known devices", "Online", "Quarantined", "Open alerts", "Events processed"],
    [counts["devices"], counts["online"], counts["quarantined"], counts["open_alerts"], counts["events"]]):
    col.metric(label, value)

st.divider()
tab_overview, tab_analytics, tab_events, tab_controls, tab_manual, tab_ingest, tab_audit = st.tabs(
    ["Overview", "Analytics & Map", "Events & Alerts", "Device Controls", "Submit Event", "Offline Analysis", "Audit Log"])

with tab_overview:
    left, right = st.columns([1.15, 1])
    with left:
        st.subheader("Device health")
        devices = db.get_devices()
        if devices:
            df = pd.DataFrame(devices)
            df["risk_score"] = df["risk_score"].astype(int)
            st.dataframe(df[["ip", "name", "device_type", "status", "risk_score", "last_seen"]],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No devices yet. Initialize the lab devices from the sidebar.")
    with right:
        st.subheader("Recent alerts")
        alerts = db.get_alerts(8)
        if alerts:
            for alert in alerts:
                icon = "🔴" if alert["severity"] == "critical" else "🟠" if alert["severity"] == "high" else "🟡"
                st.markdown(f"{icon} **{alert['title']}** · `{alert['src_ip']}` · **{alert['risk_score']}/100**")
                st.caption(f"{alert['timestamp']} · {alert['description']} · Status: {alert['status']}")
        else:
            st.info("No alerts. Try **Simulate port scan** in the sidebar.")
    st.subheader("Risk score guide")
    st.progress(0.25, text="0–39 · Low — record activity")
    st.progress(0.50, text="40–69 · Medium — create an alert")
    st.progress(0.75, text=f"70–{threshold-1} · High — alert (unless threshold is lower)")
    st.progress(1.0, text=f"{threshold}–100 · Auto-quarantine in lab mode")

with tab_analytics:
    st.subheader("Traffic and risk analytics")
    st.caption("Charts use events recorded in this database. Demo, submitted, offline, and live-capture records are labeled by source; they are not interchangeable evidence.")
    analytics_events = db.get_events(2000)
    if not analytics_events:
        st.info("No event data yet. Run a demo scenario or import an authorized event file to populate the analytics.")
    else:
        analytics_df = pd.DataFrame(analytics_events)
        analytics_df["details_obj"] = analytics_df["details"].apply(lambda value: json.loads(value) if value else {})
        analytics_df["source"] = analytics_df["details_obj"].apply(lambda value: value.get("source", "submitted / legacy"))
        analytics_df["timestamp"] = pd.to_datetime(analytics_df["timestamp"], errors="coerce", utc=True)
        left_chart, right_chart = st.columns(2)
        with left_chart:
            st.markdown("**Risk over time**")
            trend = analytics_df.dropna(subset=["timestamp"]).set_index("timestamp").sort_index()[["risk_score"]]
            if not trend.empty:
                st.line_chart(trend, y="risk_score", height=260)
        with right_chart:
            st.markdown("**Events by source**")
            source_counts = analytics_df["source"].value_counts().rename_axis("source").to_frame("events")
            st.bar_chart(source_counts, height=260)
        st.markdown("**Observed communication paths**")
        flows = analytics_df.dropna(subset=["dst_ip"]).groupby(["src_ip", "dst_ip"], as_index=False).agg(
            events=("id", "count"), latest=("timestamp", "max"), max_risk=("risk_score", "max"))
        if flows.empty:
            st.info("No source/destination pairs are available yet.")
        else:
            st.dataframe(flows.sort_values(["events", "max_risk"], ascending=False), use_container_width=True, hide_index=True)
        event_mix = analytics_df.groupby(["event_type", "source"], as_index=False).size().rename(columns={"size": "records"})
        st.markdown("**Event types by evidence source**")
        st.dataframe(event_mix, use_container_width=True, hide_index=True)

with tab_events:
    st.subheader("Event stream")
    events = db.get_events(200)
    if events:
        event_df = pd.DataFrame(events)
        event_df["details"] = event_df["details"].apply(lambda x: json.dumps(json.loads(x), ensure_ascii=False))
        st.dataframe(event_df, use_container_width=True, hide_index=True)
        st.download_button("Download events as CSV", event_df.to_csv(index=False).encode("utf-8"),
                           file_name="cybershield_events.csv", mime="text/csv")
    else:
        st.info("No events have been processed yet.")
    st.subheader("Alert register")
    alerts = db.get_alerts(200)
    if alerts:
        alert_df = pd.DataFrame(alerts)
        st.dataframe(alert_df, use_container_width=True, hide_index=True)
        st.download_button("Download alerts as CSV", alert_df.to_csv(index=False).encode("utf-8"),
                           file_name="cybershield_alerts.csv", mime="text/csv")
    else:
        st.info("No alerts yet.")
    open_alerts = [alert for alert in alerts if alert["status"] != "resolved"]
    if open_alerts:
        st.subheader("Alert triage")
        selected_alert_id = st.selectbox("Select alert", [alert["id"] for alert in open_alerts],
                                         format_func=lambda alert_id: next(
                                             f"#{alert['id']} · {alert['title']} · {alert['src_ip']} ({alert['status']})"
                                             for alert in open_alerts if alert["id"] == alert_id))
        triage_left, triage_right = st.columns(2)
        with triage_left:
            if st.button("Acknowledge alert"):
                db.update_alert_status(selected_alert_id, "acknowledged", actor="operator")
                st.rerun()
        with triage_right:
            if st.button("Resolve alert"):
                db.update_alert_status(selected_alert_id, "resolved", actor="operator")
                st.rerun()

with tab_controls:
    st.subheader("Quarantine / release controls")
    st.caption("These controls demonstrate the response workflow in the application. They do not enforce network-layer isolation.")
    devices = db.get_devices()
    if devices:
        selected_ip = st.selectbox("Select device", options=[d["ip"] for d in devices],
                                   format_func=lambda ip: f"{ip} — {next((d['name'] for d in devices if d['ip']==ip), '')}")
        selected = next(d for d in devices if d["ip"] == selected_ip)
        st.write(f"Current status: **{selected['status']}** · Risk: **{selected['risk_score']}/100**")
        c1, c2, c3 = st.columns(3)
        confirm_response = st.checkbox("Confirm this quarantine or release action", key="response_ack")
        if caps["enforces"]:
            st.caption("This provider applies real Linux firewall rules to the selected IPv4 target.")
        with c1:
            if st.button("Quarantine device", disabled=selected["status"] == "quarantined" or not confirm_response, use_container_width=True):
                result = manual_response(selected_ip, "quarantine")
                if result["success"]: st.success(f"{selected_ip}: {result['status']} · {result['message']}")
                else: st.error(f"Enforcement failed: {result['message']}")
                st.rerun()
        with c2:
            if st.button("Release / restore online", disabled=selected["status"] != "quarantined" or not confirm_response, use_container_width=True):
                result = manual_response(selected_ip, "release")
                if result["success"]: st.success(f"{selected_ip}: {result['status']} · {result['message']}")
                else: st.error(f"Release failed: {result['message']}")
                st.rerun()
        with c3:
            if st.button("Mark offline", disabled=selected["status"] == "offline", use_container_width=True):
                db.set_device_status(selected_ip, "offline", actor="operator", details="Manually marked offline")
                st.rerun()
    else:
        st.info("Initialize lab devices first.")

with tab_manual:
    st.subheader("Submit a network event")
    st.caption("Use only systems and traffic you own or are authorized to test. This form accepts event metadata; it does not generate attack traffic.")
    with st.form("event_form"):
        c1, c2 = st.columns(2)
        with c1:
            src_ip = st.text_input("Source IP", value="192.168.10.20")
            dst_ip = st.text_input("Destination IP", value="192.168.10.30")
            event_type = st.selectbox("Event type", ["normal", "port_scan", "brute_force", "traffic_spike"])
        with c2:
            unique_ports = st.number_input("Unique destination ports", min_value=0, max_value=65535, value=3)
            failed_attempts = st.number_input("Failed authentication attempts", min_value=0, max_value=100000, value=0)
            connections = st.number_input("Connections per minute", min_value=0, max_value=1000000, value=12)
        submitted = st.form_submit_button("Analyze event", type="primary")
    if submitted:
        try:
            result = process_event({"src_ip": src_ip, "dst_ip": dst_ip, "event_type": event_type,
                                    "unique_ports": int(unique_ports), "failed_attempts": int(failed_attempts),
                                    "connections_per_minute": int(connections), "source": "manual"}, threshold=threshold,
                                    detection_thresholds=rule_thresholds)
            st.session_state["last_result"] = result
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))

with tab_audit:
    st.subheader("Response audit trail")
    audit = db.get_audit_log(300)
    if audit:
        st.dataframe(pd.DataFrame(audit), use_container_width=True, hide_index=True)
        st.download_button("Download audit log as CSV", pd.DataFrame(audit).to_csv(index=False).encode("utf-8"),
                           file_name="cybershield_audit_log.csv", mime="text/csv")
    else:
        st.info("No response actions have been recorded yet.")

with tab_ingest:
    st.subheader("Import offline telemetry")
    st.caption("PCAP and event-file analysis is offline. Packet captures show observed metadata; passive packets do not prove failed connections.")
    upload = st.file_uploader("Choose a .pcap, .pcapng, .json, .csv, or .tsv file", type=["pcap", "pcapng", "json", "csv", "tsv"])
    if upload:
        if upload.size > MAX_UPLOAD_BYTES:
            st.error(f"File exceeds configured {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit.")
        elif st.button("Analyze offline file", type="primary"):
            try:
                raw = upload.getvalue()
                if upload.name.lower().endswith((".pcap", ".pcapng")):
                    records = telemetry.parse_pcap(raw, upload.name)
                else:
                    records = telemetry.parse_events(raw, upload.name)
                min_records = max(2, (rule_thresholds["connections_per_minute"] * int(detection_window) + 59) // 60)
                records = telemetry.annotate_patterns(records, int(detection_window), rule_thresholds["port_scan_ports"], min_records)
                results = [process_event(item, threshold=threshold, detection_thresholds=rule_thresholds) for item in records]
                st.success(f"Analyzed {len(results)} records from offline file.")
                st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
            except (ValueError, RuntimeError, OSError) as exc:
                st.error(str(exc))
    st.divider()
    st.subheader("Optional live capture")
    if not LIVE_CAPTURE_ENABLED:
        st.info("Disabled by default. Set CYBERSHIELD_LIVE_CAPTURE=true before starting, install Scapy, and provide OS capture permissions.")
    else:
        interfaces = telemetry.list_interfaces()
        if not interfaces: st.warning("Scapy or supported capture interfaces are unavailable.")
        else:
            iface = st.selectbox("Capture interface", interfaces)
            packet_count = st.number_input("Maximum packets", min_value=1, max_value=1000, value=100)
            if st.button("Capture selected interface"):
                try:
                    captured = telemetry.capture_live(iface, int(packet_count))
                    min_records = max(2, (rule_thresholds["connections_per_minute"] * int(detection_window) + 59) // 60)
                    captured = telemetry.annotate_patterns(captured, int(detection_window), rule_thresholds["port_scan_ports"], min_records)
                    for item in captured: item["source"] = "live_capture"
                    for item in captured: process_event(item, threshold=threshold, detection_thresholds=rule_thresholds)
                    st.success(f"Live capture completed: {len(captured)} observed records on {iface}.")
                except (ValueError, RuntimeError, OSError) as exc: st.error(str(exc))

st.divider()
st.caption("CyberShield Mesh · Student defensive security prototype · Rule-based detections are illustrative and require calibration before real-world use.")
