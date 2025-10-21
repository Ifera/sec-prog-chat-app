import asyncio
import json
import logging
import time
from typing import Dict, Optional

from websockets.asyncio.server import serve, ServerConnection
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
)

from backend.models import current_timestamp
from common import Peer, create_body
from config import config
from crypto import generate_rsa_keypair, load_private_key, compute_transport_sig
from models import (
    MsgType, HeartbeatPayload,
    generate_uuid, ServerType, ProtocolMessage
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
                ping_timeout=self.ping_timeout,
                logger=self.logger,
                ssl=config.server_ssl_context(),
        ):
            self.logger.info(f"[LISTEN] wss://{config.host}:{config.port}/ws")
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
    async def _probe_peer(self, sid: str, peer: Peer) -> bool:
        try:
            hb_pl = HeartbeatPayload(server_type=self.server_type).model_dump()
            req = self._signed_body(MsgType.HEARTBEAT, sid, hb_pl, ts=current_timestamp())
            await peer.ws.send(req)
            return True
        except Exception as e:
            self.logger.debug(f"[PROBE] failed to {sid} @ {peer.host}:{peer.port} - {e!r}")
            return False

    async def _health_monitor(self):
        hb_interval = max(3, int(config.heartbeat_interval))
        timeout_s = max(hb_interval * 2, int(config.timeout_threshold))

        while not self._stop_evt.is_set():
            start = time.time()
            peers_snapshot = list(self.peers.items())

            for sid, peer in peers_snapshot:
                host, port = peer.host, peer.port
                self.logger.debug(f"[HEALTH] Sending heartbeat to {sid} @ {host}:{port}")

                try:
                    probe_ok = await self._probe_peer(sid, peer)
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
            except Exception as e:
                self.logger.error(f"[CLOSE] Peer close {sid} failed: {e!r}")

        await self.on_peer_closed(sid)

    async def on_peer_closed(self, sid: str):
        pass

    # ---------- client disconnect ----------
    async def on_client_disconnect(self, websocket: ServerConnection):
        pass

    # ---------- incoming handling ----------
    async def _incoming(self, websocket: ServerConnection):
        sid: Optional[str] = None
        try:
            async for raw in websocket:
                try:
                    raw_json = json.loads(raw)
                except json.JSONDecodeError:
                    self.logger.error("[INCOMING] Invalid JSON frame")
                    continue

                try:
                    data = ProtocolMessage(**raw_json)
                except Exception as e:
                    self.logger.error(f"[INCOMING] Bad payload shape: {e!r}")
                    continue

                await self.handle_incoming(websocket, data.type, data)

                if not sid:
                    for psid, p in self.peers.items():
                        if p.ws is websocket:
                            sid = psid
                            break

        except (ConnectionClosedError, ConnectionClosedOK):
            pass
        except Exception as e:
            self.logger.error(f"[INCOMING] Unhandled error in connection loop: {e!r}")
        finally:
            if sid:
                await self._on_peer_closed(sid)
            else:
                try:
                    await self.on_client_disconnect(websocket)
                except Exception as e:
                    self.logger.error(f"[INCOMING] on_client_disconnect failed: {e!r}")

    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        pass

    def _signed_body(self, mtype, to, payload_dict, ts) -> str:
        sig = compute_transport_sig(load_private_key(self.server_private_key), payload_dict)
        return create_body(mtype, self.server_id, to, payload_dict, sig, ts)
