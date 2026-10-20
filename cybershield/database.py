import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DB_PATH


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str | Path | None = None) -> None:
    with connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            device_type TEXT NOT NULL DEFAULT 'Unknown',
            status TEXT NOT NULL DEFAULT 'online' CHECK(status IN ('online','quarantined','offline')),
            risk_score INTEGER NOT NULL DEFAULT 0,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            action TEXT NOT NULL DEFAULT 'observed'
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open'
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target_ip TEXT,
            details TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, target_ip TEXT NOT NULL,
            action TEXT NOT NULL, provider TEXT NOT NULL, success INTEGER NOT NULL,
            verified INTEGER NOT NULL, message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(src_ip, timestamp);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, timestamp);
        """)


def add_device(ip: str, name: str, device_type: str = "Unknown", db_path=None) -> None:
    with connect(db_path) as conn:
        conn.execute("""INSERT INTO devices(ip,name,device_type,status,risk_score,last_seen)
            VALUES(?,?,?,'online',0,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name,
            device_type=excluded.device_type,last_seen=excluded.last_seen""", (ip, name, device_type, utc_now()))


def get_devices(db_path=None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM devices ORDER BY ip DESC")]


def get_events(limit: int = 100, db_path=None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]


def get_alerts(limit: int = 100, db_path=None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))]


def get_audit_log(limit: int = 100, db_path=None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


def update_device_risk(ip: str, score: int, db_path=None) -> None:
    with connect(db_path) as conn:
        conn.execute("UPDATE devices SET risk_score=?,last_seen=? WHERE ip=?", (score, utc_now(), ip))


def set_device_status(ip: str, status: str, actor: str = "system", details: str = "", db_path=None) -> bool:
    if status not in {"online", "quarantined", "offline"}:
        raise ValueError("Unsupported device status")
    with connect(db_path) as conn:
        row = conn.execute("SELECT ip,status FROM devices WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return False
        old_status = row["status"]
        conn.execute("UPDATE devices SET status=?,last_seen=? WHERE ip=?", (status, utc_now(), ip))
        conn.execute("INSERT INTO audit_log(timestamp,actor,action,target_ip,details) VALUES(?,?,?,?,?)",
                     (utc_now(), actor, f"status:{old_status}->{status}", ip, details))
    return True


def record_event(src_ip: str, dst_ip: str | None, event_type: str, details: dict[str, Any],
                 risk_score: int, action: str, db_path=None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("INSERT INTO events(timestamp,src_ip,dst_ip,event_type,details,risk_score,action) VALUES(?,?,?,?,?,?,?)",
            (utc_now(), src_ip, dst_ip, event_type, json.dumps(details, sort_keys=True), risk_score, action))
        return int(cur.lastrowid)


def create_alert(src_ip: str, severity: str, title: str, description: str, risk_score: int, db_path=None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("INSERT INTO alerts(timestamp,src_ip,severity,title,description,risk_score) VALUES(?,?,?,?,?,?)",
            (utc_now(), src_ip, severity, title, description, risk_score))
        return int(cur.lastrowid)


def resolve_alerts_for_ip(ip: str, db_path=None) -> None:
    with connect(db_path) as conn:
        conn.execute("UPDATE alerts SET status='resolved' WHERE src_ip=? AND status='open'", (ip,))


def update_alert_status(alert_id: int, status: str, actor: str = "operator", db_path=None) -> bool:
    if status not in {"open", "acknowledged", "resolved"}:
        raise ValueError("Unsupported alert status")
    with connect(db_path) as conn:
        row = conn.execute("SELECT src_ip,status FROM alerts WHERE id=?", (int(alert_id),)).fetchone()
        if row is None:
            return False
        conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, int(alert_id)))
        conn.execute("INSERT INTO audit_log(timestamp,actor,action,target_ip,details) VALUES(?,?,?,?,?)",
                     (utc_now(), actor, f"alert:{row['status']}->{status}", row["src_ip"],
                      f"Alert {alert_id} status changed by {actor}"))
        return True


def counts(db_path=None) -> dict[str, int]:
    with connect(db_path) as conn:
        return {
            "devices": int(conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]),
            "online": int(conn.execute("SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]),
            "quarantined": int(conn.execute("SELECT COUNT(*) FROM devices WHERE status='quarantined'").fetchone()[0]),
            "open_alerts": int(conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]),
            "events": int(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]),
        }


def clear_demo_data(db_path=None) -> None:
    with connect(db_path) as conn:
        conn.executescript("DELETE FROM response_actions; DELETE FROM audit_log; DELETE FROM alerts; DELETE FROM events; DELETE FROM devices;")


def record_response(target_ip: str, action: str, result: dict[str, Any], db_path=None) -> int:
    with connect(db_path) as conn:
        cur = conn.execute("INSERT INTO response_actions(timestamp,target_ip,action,provider,success,verified,message) VALUES(?,?,?,?,?,?,?)",
            (utc_now(), target_ip, action, result.get("provider", "unknown"), int(bool(result.get("success"))),
             int(bool(result.get("verified"))), str(result.get("message", ""))))
        conn.execute("INSERT INTO audit_log(timestamp,actor,action,target_ip,details) VALUES(?,?,?,?,?)",
            (utc_now(), "response-manager", action, target_ip, json.dumps(result, sort_keys=True)))
        return int(cur.lastrowid)


def get_response_actions(limit: int = 100, db_path=None) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM response_actions ORDER BY id DESC LIMIT ?", (limit,))]
