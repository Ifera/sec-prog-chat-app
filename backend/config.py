import json
import logging
import os
import ssl
from typing import List, Dict, Any


class Config:
    def __init__(self):
        # Core server settings
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = int(os.getenv("PORT", "8082"))
        self.logging_level = logging.DEBUG
        self.logging_format = "[%(asctime)s] [%(levelname)s] [%(module)s.%(funcName)s::%(lineno)s] [%(name)s] %(message)s"

        self.tls_cert = os.getenv("TLS_CERT", "dev_cert.pem")
        self.tls_key = os.getenv("TLS_KEY", "dev_key.pem")
        self.tls_skip_verify: bool = os.getenv("TLS_SKIP_VERIFY", "true").lower() == "true"

        # DB
        self.db_path: str = os.getenv("DB_PATH", "chat.db")

        # Health
        self.heartbeat_interval: int = int(os.getenv("HEARTBEAT_INTERVAL", "15"))  # seconds
        self.timeout_threshold: int = int(os.getenv("TIMEOUT_THRESHOLD", "45"))  # seconds

        self.max_file_size: int = int(os.getenv("MAX_FILE_SIZE", 1024 * 1024 * 2))  # 2 MB

        # Introducer JSON file (preferred)
        introducer_json_path = os.getenv("INTRODUCERS_JSON", "introducers.json")
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

    def server_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)
        return ctx

    def client_ssl_context(self) -> ssl.SSLContext | None:
        if self.tls_skip_verify:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            return ctx
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        return ctx


config = Config()
