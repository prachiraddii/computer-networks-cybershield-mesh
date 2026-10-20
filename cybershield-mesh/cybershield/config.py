from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("CYBERSHIELD_DB_PATH", BASE_DIR / "data" / "cybershield.db"))
RISK_THRESHOLD = int(os.getenv("CYBERSHIELD_RISK_THRESHOLD", "75"))
APP_NAME = "CyberShield Mesh"
MAX_UPLOAD_BYTES = int(os.getenv("CYBERSHIELD_MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
LIVE_CAPTURE_ENABLED = os.getenv("CYBERSHIELD_LIVE_CAPTURE", "false").lower() == "true"
ENFORCEMENT_MODE = os.getenv("CYBERSHIELD_ENFORCEMENT", "simulation").lower()
DETECTION_THRESHOLDS = {
    "port_scan_ports": int(os.getenv("CYBERSHIELD_PORT_SCAN_PORTS", "20")),
    "failed_attempts": int(os.getenv("CYBERSHIELD_FAILED_ATTEMPTS", "10")),
    "connections_per_minute": int(os.getenv("CYBERSHIELD_CONNECTIONS_PER_MINUTE", "120")),
}
DETECTION_WINDOW_SECONDS = int(os.getenv("CYBERSHIELD_DETECTION_WINDOW_SECONDS", "60"))
