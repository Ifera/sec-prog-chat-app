import json
import os
from typing import List, Dict, Any


class Config:
    def __init__(self):
        # Core server settings
        self.host: str = os.getenv("SOCP_HOST", "0.0.0.0")
        self.port: int = int(os.getenv("SOCP_PORT", "8082"))
        self.is_introducer: bool = os.getenv("SOCP_IS_INTRODUCER", "false").lower() == "true"

        # DB
        self.db_path: str = os.getenv("SOCP_DB_PATH", "socp.db")

        # Health
        self.heartbeat_interval: int = int(os.getenv("HEARTBEAT_INTERVAL", "15"))  # seconds
        self.timeout_threshold: int = int(os.getenv("TIMEOUT_THRESHOLD", "45"))  # seconds

        # Introducer JSON file (preferred)
        introducer_json_path = os.getenv("SOCP_INTRODUCERS_JSON", "introducers.json")
        self.bootstrap_servers: List[Dict[str, Any]] = []
        try:
            with open(introducer_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.bootstrap_servers = data.get("bootstrap_servers", [])
        except Exception:
            # Fallback to envs (compatible with old scripts)
            self.bootstrap_servers = [
                {
                    "host": os.getenv("BOOTSTRAP_HOST_1", "127.0.0.1").strip(),
                    "port": int(os.getenv("BOOTSTRAP_PORT_1", "8081").strip()),
                    "pubkey": os.getenv("BOOTSTRAP_PUBKEY_1", "")
                },
                {
                    "host": os.getenv("BOOTSTRAP_HOST_2", "127.0.0.1").strip(),
                    "port": int(os.getenv("BOOTSTRAP_PORT_2", "8083").strip()),
                    "pubkey": os.getenv("BOOTSTRAP_PUBKEY_2", "")
                },
                {
                    "host": os.getenv("BOOTSTRAP_HOST_3", "127.0.0.1").strip(),
                    "port": int(os.getenv("BOOTSTRAP_PORT_3", "8085").strip()),
                    "pubkey": os.getenv("BOOTSTRAP_PUBKEY_3", "")
                }
            ]


config = Config()
