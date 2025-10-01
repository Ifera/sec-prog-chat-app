import asyncio
import json
import logging
import time
from typing import Dict, Optional

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve, ServerConnection
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
)

from common import Peer
from config import config
from crypto import generate_rsa_keypair
from models import (
    MsgType, HeartbeatPayload,
    current_timestamp, generate_uuid, ServerType
)

logging.basicConfig(level=config.logging_level, format=config.logging_format)


class BaseServer:

    def __init__(
            self,
            server_type: ServerType,
            logger: logging.Logger,
            ping_interval: float | None,
            ping_timeout: float | None
    ):
        self.server_type = server_type
        self.logger = logger
        self.ping_interval = ping_interval
        self.ping_timeout = ping_timeout

        self.server_id: Optional[str] = None
        self.server_private_key: Optional[str] = None
        self.server_public_key: Optional[str] = None

        # connected peers (servers only)
        self.peers: Dict[str, Peer] = {}  # sid -> Peer

        # shutdown controls
        self._stop_evt = asyncio.Event()
        self._bg_tasks: set[asyncio.Task] = set()

    # ---------- lifecycle ----------
    def init_server(self):
        self.server_id = generate_uuid()
        self.server_private_key, self.server_public_key = generate_rsa_keypair()
        self.logger.info(f"[BOOT] {self.server_type} ID: {self.server_id} @ {config.host}:{config.port}")

    async def start(self):
        self.init_server()

        await self.on_start()

        if self.ping_interval is None and self.ping_timeout is None:
            self._bg_tasks.add(asyncio.create_task(self._health_monitor(), name="health-monitor"))
            self.logger.info("[HEALTH] Health monitor registered")

        async with serve(
                self._incoming,
                config.host,
                config.port,
                ping_interval=self.ping_interval,
                ping_timeout=self.ping_timeout
        ):
            self.logger.info(f"[LISTEN] ws://{config.host}:{config.port}/ws")
            try:
                await self._stop_evt.wait()
            except asyncio.CancelledError:
                pass
            finally:
                await self._shutdown_cleanup()

    async def on_start(self):
        pass

    async def shutdown(self, reason: str = "shutdown"):
        if not self._stop_evt.is_set():
            self.logger.info(f"[STOP] Shutting down {reason}...")
            await self.on_shutdown(reason)
            self._stop_evt.set()

    async def on_shutdown(self, reason: str):
        pass

    async def _shutdown_cleanup(self):
        for t in list(self._bg_tasks):
            if not t.done():
                t.cancel()

        await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        self._bg_tasks.clear()

        # close server links
        for sid, peer in list(self.peers.items()):
            try:
                await peer.ws.close()
            except Exception:
                self.logger.error(f"[CLOSE] Closing peer {sid} failed")

        self.peers.clear()
        await self.on_shutdown_cleanup()
        self.logger.info("[STOP] Shutdown complete")

    async def on_shutdown_cleanup(self):
        pass

    # ---------- HEALTH / HEARTBEAT ----------
    async def _probe_peer(self, sid: str, host: str, port: int) -> bool:
        uri = f"ws://{host}:{port}/ws"
        try:
            async with connect(uri) as conn:  # auto-closes
                hb = {
                    "type": MsgType.HEARTBEAT,
                    "from": self.server_id,
                    "to": sid,
                    "ts": current_timestamp(),
                    "payload": HeartbeatPayload(server_type=self.server_type).model_dump(),
                    "sig": "",
                }
                await asyncio.wait_for(conn.send(json.dumps(hb)), timeout=3)
                return True
        except Exception:
            self.logger.error(f"[PROBE] failed to {sid} @ {host}:{port}")
            return False

    async def _health_monitor(self):
        """
        Every HEARTBEAT_INTERVAL seconds:
          1) Open a NEW websocket connection to each peer's host:port
          2) Send app-level HEARTBEAT over that fresh connection (probe)
          3) If probe fails repeatedly or last_seen is too old, drop peer
        """
        hb_interval = max(3, int(config.heartbeat_interval))
        timeout_s = max(hb_interval * 2, int(config.timeout_threshold))

        while not self._stop_evt.is_set():
            start = time.time()
            peers_snapshot = list(self.peers.items())

            for sid, peer in peers_snapshot:
                host, port = peer.host, peer.port
                self.logger.info(f"[HEALTH] Sending heartbeat to {sid} @ {host}:{port}")

                try:
                    probe_ok = await self._probe_peer(sid, host, port)
                    now = time.time()

                    if probe_ok:
                        peer.last_seen = now
                        peer.missed = 0
                    else:
                        peer.missed += 1
                        self.logger.warning(f"[HEALTH] Probe failed for {sid} (missed={peer.missed})")

                        quiet = now - peer.last_seen
                        if quiet > timeout_s or peer.missed >= 2:
                            self.logger.warning(
                                f"[HEALTH] {sid} timed out (quiet={quiet:.1f}s, missed={peer.missed}); removing")
                            await self._on_peer_closed(sid, timed_out=True)
                            continue

                except Exception:
                    self.logger.error(f"[HEALTH] Unexpected error while probing {sid}")
                    peer.missed += 1
                    if peer.missed >= 2:
                        await self._on_peer_closed(sid, timed_out=True)

            elapsed = time.time() - start
            await asyncio.sleep(max(0.0, hb_interval - elapsed))

    # ---------- peer close ----------
    async def _on_peer_closed(self, sid: str, timed_out: bool = False):
        peer = self.peers.pop(sid, None)

        if peer:
            try:
                await peer.ws.close()
                reason = "timeout" if timed_out else "disconnect"
                self.logger.info(f"Closed peer: {sid} due to {reason}")
            except Exception:
                self.logger.error(f"[CLOSE] Peer close {sid} failed")

        await self.on_peer_closed(sid)

    async def on_peer_closed(self, sid: str):
        pass

    # ---------- incoming handling ----------
    async def _incoming(self, websocket: ServerConnection):
        try:
            first_raw = await websocket.recv()
            data = json.loads(first_raw)
            req_type = data.get("type")
            self.logger.info(f"[INCOMING] Request Type: {req_type}")
            await self.handle_incoming(websocket, req_type, data)
        except (ConnectionClosedError, ConnectionClosedOK):
            pass
        except json.JSONDecodeError:
            self.logger.error("[INCOMING] Invalid JSON on first frame")
        except Exception:
            self.logger.error("[INCOMING] Error in first frame handling")

    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: dict):
        pass
