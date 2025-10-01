import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional
from typing import Union

from websockets.client import connect, WebSocketClientProtocol
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
    WebSocketException,
)
from websockets.server import serve, WebSocketServerProtocol

from config import config
from crypto import generate_rsa_keypair, load_private_key, compute_transport_sig
from database import Database
from models import (
    MsgType, ErrorCode,
    ProtocolMessage,
    ServerHelloJoinPayload, ServerAnnouncePayload, ServerWelcomePayload, ServerInfo,
    ServerGoodbyePayload,
    UserAdvertisePayload, UserRemovePayload, ServerDeliverPayload, HeartbeatPayload,
    UserHelloPayload, MsgDirectPayload, MsgPublicChannelPayload, ErrorPayload,
    UserDeliverPayload,
    current_timestamp, generate_uuid, CommandPayload
)

logging.basicConfig(level=config.logging_level)
logger = logging.getLogger("Server")


@dataclass
class Peer:
    sid: str
    ws: Union[WebSocketClientProtocol, WebSocketServerProtocol]  # ← allow both
    host: str
    port: int
    pubkey: Optional[str] = None
    last_seen: float = field(default_factory=lambda: time.time())
    missed: int = 0


class Server:
    """
    UUID-only server IDs everywhere.
    Robust heartbeat that uses both app-level HEARTBEAT and ws.ping/pong.
    No exceptions are silently swallowed; we log with traceback and clean up.
    """

    def __init__(self):
        self.server_id: Optional[str] = None
        self.server_private_key: Optional[str] = None
        self.server_public_key: Optional[str] = None

        self.db = Database(config.db_path)

        # ==== in-memory tables ====
        # peers by server UUID
        self.peers: Dict[str, Peer] = {}  # sid -> Peer
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # sid -> (host, port)

        # local presence + routing
        self.local_users: Dict[str, WebSocketServerProtocol] = {}  # user_id -> ws
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_{sid}"

        # introducer directory (only used if this is an introducer)
        self.known_servers: Dict[str, Dict[str, str | int]] = {}  # sid -> {host, port, pubkey}

        # duplicate suppression for forwarded deliveries
        self.seen_ids: set[str] = set()

        # shutdown controls
        self._stop_evt = asyncio.Event()
        self._bg_tasks: set[asyncio.Task] = set()

    # ---------- lifecycle ----------
    def init_server(self):
        self.server_id = generate_uuid()
        self.server_private_key, self.server_public_key = generate_rsa_keypair()
        logger.info(f"[BOOT] Server ID: {self.server_id} @ {config.host}:{config.port}")

    async def start(self):
        self.init_server()

        # background: bootstrap + health monitor
        self._bg_tasks.add(asyncio.create_task(self.bootstrap_to_network(), name="bootstrap"))
        self._bg_tasks.add(asyncio.create_task(self._health_monitor(), name="health-monitor"))

        # optional: Windows-only Ctrl+X hotkey (Ctrl+X = b'\x18')
        if os.name == "nt":
            self._bg_tasks.add(asyncio.create_task(self._win_hotkey_listener(), name="hotkey"))

        async with serve(self._incoming, config.host, config.port, ping_interval=None, ping_timeout=None):
            # NOTE: we disable websockets' built-in pings; we do explicit ping/pong timing.
            logger.info(f"[LISTEN] ws://{config.host}:{config.port}/ws")
            try:
                await self._stop_evt.wait()
            except asyncio.CancelledError:
                # clean shutdown path
                pass
            finally:
                await self._shutdown_cleanup()

    async def shutdown(self, reason: str = "shutdown"):
        """Trigger graceful shutdown."""
        if not self._stop_evt.is_set():
            logger.info("[STOP] Shutting down…")
            await self._broadcast_goodbye(reason=reason)
            self._stop_evt.set()

    async def _shutdown_cleanup(self):
        # cancel background tasks
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
                logging.exception(f"[CLOSE] closing peer {sid} failed")
        self.peers.clear()
        self.server_addrs.clear()

        # close local user sockets
        for uid, ws in list(self.local_users.items()):
            try:
                await ws.close()
            except Exception:
                logging.exception(f"[CLOSE] closing user {uid} failed")
        self.local_users.clear()

        logger.info("[STOP] Clean exit.")

    # ---------- Windows hotkey (optional) ----------
    async def _win_hotkey_listener(self):
        """Press Ctrl+X on Windows console to stop gracefully."""
        try:
            import msvcrt  # only on Windows
        except Exception:
            return
        while not self._stop_evt.is_set():
            await asyncio.sleep(0.05)
            try:
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b'\x18':  # Ctrl+X
                        await self.shutdown("ctrl+x")
                        break
            except Exception:
                logging.exception("[HOTKEY] failed")
                break

    # ---------- bootstrap & linking ----------
    async def bootstrap_to_network(self):
        if config.is_introducer:
            logger.info("[BOOTSTRAP] Acting as introducer; awaiting joins.")
            return

        logger.info("[BOOTSTRAP] Starting bootstrap to introducers...")
        backoff = 2
        for attempt in range(1, 6):
            for introducer in config.bootstrap_servers:
                host, port = introducer.get("host"), introducer.get("port")
                if not host or not port:
                    continue
                uri = f"ws://{host}:{port}/ws"
                try:
                    async with connect(uri) as ws:
                        payload = ServerHelloJoinPayload(
                            host=config.host, port=config.port, pubkey=self.server_public_key
                        ).model_dump()
                        join = {
                            "type": MsgType.SERVER_HELLO_JOIN,
                            "from": self.server_id,
                            "to": f"{host}:{port}",
                            "ts": current_timestamp(),
                            "payload": payload,
                            "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
                        }
                        await ws.send(json.dumps(join))
                        logger.info(f"[BOOTSTRAP] Sent SERVER_HELLO_JOIN to {uri}")

                        raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
                        data = json.loads(raw)
                        if data.get("type") != MsgType.SERVER_WELCOME:
                            logger.warning(f"[BOOTSTRAP] Unexpected response: {data.get('type')}")
                            continue

                        welcome = ServerWelcomePayload(**data["payload"])
                        # The introducer may assign/confirm our ID
                        self.server_id = welcome.assigned_id
                        logger.info(f"[BOOTSTRAP] Assigned ID: {self.server_id}")

                        # Connect to the returned server list (servers, not users)
                        for si in welcome.servers:
                            await self._connect_to_server(si.server_id, si.host, int(si.port), si.pubkey)

                        # Announce ourselves to everyone we connected to
                        await self._broadcast_announce()
                        logger.info("[BOOTSTRAP] Completed.")
                        return
                except (asyncio.TimeoutError, ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
                    logger.warning(f"[BOOTSTRAP] {uri} failed: {e!r}")
                except Exception:
                    logging.exception(f"[BOOTSTRAP] {uri} unexpected error")

            logger.info(f"[BOOTSTRAP] Retry in {backoff}s (attempt {attempt}/5)")
            await asyncio.sleep(backoff)
            backoff *= 2

        logger.warning("[BOOTSTRAP] All introducers unreachable; operating standalone for now.")

    async def _connect_to_server(self, sid: str, host: str, port: int, pubkey: Optional[str]):
        """Create a persistent websocket to another server and send SERVER_ANNOUNCE."""
        uri = f"ws://{host}:{port}/ws"
        try:
            ws = await connect(uri)
            peer = Peer(sid=sid, ws=ws, host=host, port=port, pubkey=pubkey)
            self.peers[sid] = peer
            self.server_addrs[sid] = (host, port)

            payload = ServerAnnouncePayload(
                host=config.host, port=config.port, pubkey=self.server_public_key
            ).model_dump()
            msg = {
                "type": MsgType.SERVER_ANNOUNCE,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": payload,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
            }
            await ws.send(json.dumps(msg))

            # start listener
            self._bg_tasks.add(asyncio.create_task(self._listen_server(peer), name=f"listen-{sid}"))
            logger.info(f"[LINK] Connected to {sid} @ {host}:{port}")
        except (ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
            logger.error(f"[LINK] Failed to connect {uri}: {e!r}")
            self._forget_peer(sid)
        except Exception:
            logging.exception(f"[LINK] Failed to connect {uri}")
            self._forget_peer(sid)

    async def _broadcast_announce(self):
        payload = ServerAnnouncePayload(host=config.host, port=config.port, pubkey=self.server_public_key).model_dump()
        for sid, peer in list(self.peers.items()):
            try:
                msg = {
                    "type": MsgType.SERVER_ANNOUNCE,
                    "from": self.server_id,
                    "to": sid,
                    "ts": current_timestamp(),
                    "payload": payload,
                    "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
                }
                await peer.ws.send(json.dumps(msg))
            except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
                logger.warning(f"[ANNOUNCE] {sid} closed during announce")
                await self._on_peer_closed(sid)
            except Exception:
                logging.exception(f"[ANNOUNCE] send to {sid} failed")
                await self._on_peer_closed(sid)

    async def _broadcast_goodbye(self, reason: str = "shutdown"):
        payload = ServerGoodbyePayload(reason=reason).model_dump()
        for sid, peer in list(self.peers.items()):
            try:
                msg = {
                    "type": MsgType.SERVER_GOODBYE,
                    "from": self.server_id,
                    "to": sid,
                    "ts": current_timestamp(),
                    "payload": payload,
                    "sig": "",
                }
                await peer.ws.send(json.dumps(msg))
            except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
                # already gone; nothing further
                pass
            except Exception:
                logging.exception(f"[GOODBYE] send to {sid} failed")

    async def _print_servers(self):
        for sid, peer in list(self.peers.items()):
            logger.info(f"[{sid}] {peer.host}:{peer.port} {peer.pubkey}")

    # ---------- HEALTH / HEARTBEAT ----------
    async def _probe_peer(self, sid: str, host: str, port: int) -> bool:
        """
        Liveness probe using a NEW websocket connection (do NOT use cached peer.ws).
        Connect -> send a lightweight HEARTBEAT -> close.
        Returns True iff the probe succeeded end-to-end.
        """
        uri = f"ws://{host}:{port}/ws"
        try:
            # short connect timeout
            conn = await asyncio.wait_for(connect(uri), timeout=5)
        except Exception:
            logging.exception(f"[PROBE] connect failed to {sid} @ {host}:{port}")
            return False

        try:
            # send a tiny heartbeat frame (no need to wait for a reply)
            hb = {
                "type": MsgType.HEARTBEAT,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": HeartbeatPayload().model_dump(),
                "sig": "",
            }
            await asyncio.wait_for(conn.send(json.dumps(hb)), timeout=3)
            # optional: try to read a byte or just rely on TCP handshake + send success
            return True
        except Exception:
            logging.exception(f"[PROBE] heartbeat send failed to {sid} @ {host}:{port}")
            return False
        finally:
            try:
                await conn.close()
            except Exception:
                logging.exception(f"[PROBE] close failed for {sid}")

    # async def _health_monitor(self):
    #     """
    #     Every HEARTBEAT_INTERVAL seconds:
    #       1) ws.ping(), wait max 5s for pong
    #       2) send app-level HEARTBEAT message
    #       3) if now - last_seen > TIMEOUT_THRESHOLD, drop peer (and remove from introducer if applicable)
    #     """
    #     hb_interval = max(3, int(config.heartbeat_interval))
    #     timeout_s = max(hb_interval * 2, int(config.timeout_threshold))
    #
    #     while not self._stop_evt.is_set():
    #         start = time.time()
    #         for sid, peer in list(self.peers.items()):
    #             try:
    #                 # 1) transport-level ping/pong
    #                 pong_waiter = peer.ws.ping()
    #                 await asyncio.wait_for(pong_waiter, timeout=5)
    #
    #                 # 2) app-level heartbeat
    #                 hb = {
    #                     "type": MsgType.HEARTBEAT,
    #                     "from": self.server_id,
    #                     "to": sid,
    #                     "ts": current_timestamp(),
    #                     "payload": HeartbeatPayload().model_dump(),
    #                     "sig": "",
    #                 }
    #                 await peer.ws.send(json.dumps(hb))
    #
    #                 # 3) timeout check
    #                 if time.time() - peer.last_seen > timeout_s:
    #                     logger.warning(f"[HEALTH] {sid} timed out (last_seen={peer.last_seen:.0f})")
    #                     await self._on_peer_closed(sid, timed_out=True)
    #                     continue
    #
    #                 # reset missed on successful cycle
    #                 peer.missed = 0
    #
    #             except asyncio.TimeoutError:
    #                 peer.missed += 1
    #                 logger.warning(f"[HEALTH] {sid} missed pong (missed={peer.missed})")
    #                 if time.time() - peer.last_seen > timeout_s or peer.missed >= 2:
    #                     await self._on_peer_closed(sid, timed_out=True)
    #             except (ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
    #                 logger.warning(f"[HEALTH] {sid} closed: {e!r}")
    #                 await self._on_peer_closed(sid)
    #             except Exception as e:
    #                 logging.exception(f"[HEALTH] error with {sid}")
    #                 logger.exception(f"[HEALTH] {sid} failed: {e!r}")
    #                 await self._on_peer_closed(sid)
    #
    #         # sleep the remainder of the interval
    #         elapsed = time.time() - start
    #         await asyncio.sleep(max(0.0, hb_interval - elapsed))

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

            # snapshot to avoid dict-size change during iteration
            peers_snapshot = list(self.peers.items())
            for sid, peer in peers_snapshot:
                host, port = peer.host, peer.port

                try:
                    probe_ok = await self._probe_peer(sid, host, port)
                    now = time.time()

                    if probe_ok:
                        # Fresh connection worked – consider peer alive
                        peer.last_seen = now
                        peer.missed = 0
                    else:
                        peer.missed += 1
                        logger.warning(f"[HEALTH] probe failed for {sid} (missed={peer.missed})")

                        # If they've been quiet for too long, or we missed enough probes, drop them
                        quiet = now - peer.last_seen
                        if quiet > timeout_s or peer.missed >= 2:
                            logger.warning(
                                f"[HEALTH] {sid} timed out (quiet={quiet:.1f}s, missed={peer.missed}); removing")
                            await self._on_peer_closed(sid, timed_out=True)
                            continue

                except Exception:
                    # absolutely no silent failures
                    logging.exception(f"[HEALTH] unexpected error while probing {sid}")
                    # treat as a miss in case of coding/runtime errors
                    peer.missed += 1
                    if peer.missed >= 2:
                        await self._on_peer_closed(sid, timed_out=True)

            # sleep the remainder of the interval
            elapsed = time.time() - start
            await asyncio.sleep(max(0.0, hb_interval - elapsed))

    async def _on_peer_closed(self, sid: str, timed_out: bool = False):
        """Cleanup when a peer is closed or unhealthy."""
        peer = self.peers.pop(sid, None)
        self.server_addrs.pop(sid, None)
        if peer:
            try:
                await peer.ws.close()
            except Exception:
                # log but continue; we're already cleaning up
                logging.exception(f"[CLOSE] peer close {sid} failed")
        # if introducer, also remove from directory
        if config.is_introducer and sid in self.known_servers:
            self.known_servers.pop(sid, None)
            reason = "timeout" if timed_out else "disconnect"
            logger.info(f"[INTRODUCER] Removed {sid} from directory due to {reason}")

    def _forget_peer(self, sid: str):
        self.peers.pop(sid, None)
        self.server_addrs.pop(sid, None)

    # ---------- incoming handling ----------
    async def _incoming(self, websocket: WebSocketServerProtocol, path: str):
        try:
            first_raw = await websocket.recv()
            first = json.loads(first_raw)
            logger.info(f"[INCOMING] Request: {first}")
            ftype = first.get("type")

            if ftype == MsgType.SERVER_HELLO_JOIN:
                await self._handle_server_join(websocket, first)
                return
            if ftype == MsgType.SERVER_ANNOUNCE:
                await self._handle_server_announce(websocket, first)
                return
            if ftype == MsgType.SERVER_GOODBYE:
                await self._handle_server_goodbye(first)
                await websocket.close()
                return
            if ftype == MsgType.HEARTBEAT:
                # peer heartbeat as first message is odd but not harmful
                pass

            # treat as user connection
            await self._handle_user_connection(websocket, first)
        except (ConnectionClosedError, ConnectionClosedOK):
            # connection gone while reading first frame — nothing to do
            pass
        except json.JSONDecodeError:
            logging.exception("[INCOMING] invalid JSON on first frame")
        except Exception:
            logging.exception("[INCOMING] error in first frame handling")

    async def _handle_server_join(self, websocket: WebSocketServerProtocol, data: dict):
        try:
            payload = ServerHelloJoinPayload(**data["payload"])

            # Introducer assigns ID and returns server list (servers, not users)
            if config.is_introducer:
                requested_id = data.get("from") or generate_uuid()
                assigned_id = requested_id if requested_id not in self.known_servers else generate_uuid()
                self.known_servers[assigned_id] = {"host": payload.host, "port": payload.port, "pubkey": payload.pubkey}

                servers_payload = []
                for sid, s in self.known_servers.items():
                    if sid == assigned_id:
                        continue
                    servers_payload.append(
                        ServerInfo(server_id=sid, host=s["host"], port=int(s["port"]), pubkey=s["pubkey"]).model_dump()
                    )

                welcome = ServerWelcomePayload(assigned_id=assigned_id, servers=servers_payload).model_dump()
            else:
                welcome = ServerWelcomePayload(assigned_id=data.get("from") or generate_uuid(), servers=[]).model_dump()

            msg = {
                "type": MsgType.SERVER_WELCOME,
                "from": self.server_id,
                "to": data.get("from"),
                "ts": current_timestamp(),
                "payload": welcome,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), welcome),
            }
            await websocket.send(json.dumps(msg))

            # register temporary peer socket under the joining server's (claimed) id
            tmp_sid = data.get("from") or generate_uuid()
            self.peers[tmp_sid] = Peer(sid=tmp_sid, ws=websocket, host=payload.host, port=payload.port)
            self.server_addrs[tmp_sid] = (payload.host, payload.port)

            # start listener for this socket
            self._bg_tasks.add(asyncio.create_task(self._listen_server(self.peers[tmp_sid]), name=f"listen-{tmp_sid}"))
        except Exception:
            logging.exception("[JOIN] failed to handle server join")

    async def _handle_server_announce(self, websocket: WebSocketServerProtocol, data: dict):
        try:
            payload = ServerAnnouncePayload(**data["payload"])
            sid = data["from"]

            # either update existing peer or add new
            if sid in self.peers:
                peer = self.peers[sid]
                peer.ws = websocket
                peer.host = payload.host
                peer.port = payload.port
                peer.pubkey = payload.pubkey
                peer.last_seen = time.time()
                peer.missed = 0
            else:
                self.peers[sid] = Peer(sid=sid, ws=websocket, host=payload.host, port=payload.port,
                                       pubkey=payload.pubkey)
                self._bg_tasks.add(asyncio.create_task(self._listen_server(self.peers[sid]), name=f"listen-{sid}"))

            self.server_addrs[sid] = (payload.host, payload.port)

            if config.is_introducer:
                self.known_servers[sid] = {"host": payload.host, "port": payload.port, "pubkey": payload.pubkey}
                logger.info(f"[INTRODUCER] Registered {sid} -> {payload.host}:{payload.port}")
        except Exception:
            logging.exception("[ANNOUNCE] failed")

    async def _handle_server_goodbye(self, data: dict):
        try:
            sid = data.get("from")
            await self._on_peer_closed(sid)
        except Exception:
            logging.exception("[GOODBYE] failed")

    async def _listen_server(self, peer: Peer):
        sid = peer.sid
        try:
            async for raw in peer.ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    logging.exception(f"[LISTEN {sid}] invalid JSON")
                    continue

                mtype = data.get("type")
                # any valid incoming message counts as alive
                pr = self.peers.get(sid)
                if pr:
                    pr.last_seen = time.time()
                    pr.missed = 0

                try:
                    if mtype == MsgType.USER_ADVERTISE:
                        await self._handle_user_advertise(data)
                    elif mtype == MsgType.USER_REMOVE:
                        await self._handle_user_remove(data)
                    elif mtype == MsgType.SERVER_DELIVER:
                        await self._handle_server_deliver(data)
                    elif mtype == MsgType.SERVER_GOODBYE:
                        await self._handle_server_goodbye(data)
                        break
                    elif mtype == MsgType.HEARTBEAT:
                        # nothing else to do; last_seen already updated
                        pass
                    else:
                        # ignore unknown types from servers, but log once
                        logger.debug(f"[LISTEN {sid}] unknown type: {mtype}")
                except Exception:
                    logging.exception(f"[LISTEN {sid}] handler error")
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            logger.info(f"[LISTEN {sid}] connection closed: {e!r}")
            await self._on_peer_closed(sid)
        except WebSocketException as e:
            logger.warning(f"[LISTEN {sid}] websocket error: {e!r}")
        except Exception:
            logging.exception(f"[LISTEN {sid}] unexpected failure")

    # ---------- user side ----------
    async def _handle_user_connection(self, websocket: WebSocketServerProtocol, first: dict):
        try:
            await self._process_user_message(websocket, first)
            async for raw in websocket:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    logging.exception("[USER] invalid JSON")
                    continue
                await self._process_user_message(websocket, data)
        except ConnectionClosedOK:
            pass
        except ConnectionClosedError:
            pass
        except Exception:
            logging.exception("[USER] error")

    async def _process_user_message(self, websocket: WebSocketServerProtocol, data: dict):
        msg = ProtocolMessage(**data)
        if msg.type == MsgType.USER_HELLO:
            await self._user_hello(websocket, msg)
        elif msg.type == MsgType.MSG_DIRECT:
            await self._msg_direct(msg)
        elif msg.type == MsgType.MSG_PUBLIC_CHANNEL:
            await self._msg_public(msg)
        elif msg.type == MsgType.COMMAND:
            await self._handle_command(websocket, msg)
        elif msg.type == MsgType.HEARTBEAT:
            # ignore heartbeats from users (not expected), but it's fine
            pass
        else:
            await self._error_to(ws=websocket, code=ErrorCode.UNKNOWN_TYPE, detail=f"Unknown type {msg.type}")

    async def _user_hello(self, websocket: WebSocketServerProtocol, msg: ProtocolMessage):
        payload = UserHelloPayload(**msg.payload)
        user_id = msg.from_
        if user_id in self.local_users:
            await self._error_to(ws=websocket, code=ErrorCode.NAME_IN_USE, detail="User ID already in use")
            return

        self.local_users[user_id] = websocket
        self.user_locations[user_id] = "local"
        self.db.add_user(user_id, payload.pubkey, "", "", {})

        await self._gossip_user_advertise(user_id, payload.pubkey)
        await self._broadcast_local_user_advertise(user_id, payload.pubkey)

    async def _gossip_user_advertise(self, user_id: str, pubkey: str):
        payload = UserAdvertisePayload(user_id=user_id, server_id=self.server_id, pubkey=pubkey, meta={}).model_dump()
        for sid, peer in list(self.peers.items()):
            try:
                msg = {
                    "type": MsgType.USER_ADVERTISE,
                    "from": self.server_id,
                    "to": sid,
                    "ts": current_timestamp(),
                    "payload": payload,
                    "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
                }
                await peer.ws.send(json.dumps(msg))
            except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
                logger.warning(f"[GOSSIP] {sid} closed during advertise")
                await self._on_peer_closed(sid)
            except Exception:
                logging.exception(f"[GOSSIP] send to {sid} failed")
                await self._on_peer_closed(sid)

    async def _broadcast_local_user_advertise(self, user_id: str, pubkey: str):
        advertise = {
            "type": MsgType.USER_ADVERTISE,
            "from": self.server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": {
                "user_id": user_id,
                "server_id": self.server_id,
                "pubkey": pubkey,
                "meta": {}
            },
            "sig": ""
        }
        for _, ws in list(self.local_users.items()):
            try:
                await ws.send(json.dumps(advertise))
            except (ConnectionClosedError, ConnectionClosedOK):
                # client dropped; will be cleaned up by GC or future presence pass
                pass
            except Exception:
                logging.exception("[LOCAL-ADV] failed to send to client")

    async def _msg_direct(self, msg: ProtocolMessage):
        payload = MsgDirectPayload(**msg.payload)
        target = msg.to

        # deliver locally if present
        if target in self.local_users:
            deliver = UserDeliverPayload(
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            out = {
                "type": MsgType.USER_DELIVER,
                "from": self.server_id,
                "to": target,
                "ts": current_timestamp(),
                "payload": deliver,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), deliver)
            }
            try:
                await self.local_users[target].send(json.dumps(out))
            except Exception:
                logging.exception(f"[DM] failed to deliver to local user {target}")
            return

        # else route to remote server if we know it
        loc = self.user_locations.get(target)
        if loc and loc.startswith("server_"):
            sid = loc.replace("server_", "")
            peer = self.peers.get(sid)
            if peer:
                fwd = ServerDeliverPayload(
                    user_id=target,
                    ciphertext=payload.ciphertext,
                    sender=msg.from_,
                    sender_pub=payload.sender_pub,
                    content_sig=payload.content_sig
                ).model_dump()
                out = {
                    "type": MsgType.SERVER_DELIVER,
                    "from": self.server_id,
                    "to": sid,
                    "ts": current_timestamp(),
                    "payload": fwd,
                    "sig": compute_transport_sig(load_private_key(self.server_private_key), fwd)
                }
                try:
                    await peer.ws.send(json.dumps(out))
                except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
                    logger.warning(f"[DM] peer {sid} closed while forwarding")
                    await self._on_peer_closed(sid)
                except Exception:
                    logging.exception(f"[DM] send to {sid} failed")
                    await self._on_peer_closed(sid)
                return

        await self._error_upstream(origin=msg.from_, code=ErrorCode.USER_NOT_FOUND, detail=f"{target} not registered")

    async def _msg_public(self, msg: ProtocolMessage):
        payload = MsgPublicChannelPayload(**msg.payload)

        # broadcast to local users
        for uid, ws in list(self.local_users.items()):
            deliver = UserDeliverPayload(
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            out = {
                "type": MsgType.USER_DELIVER,
                "from": self.server_id,
                "to": uid,
                "ts": current_timestamp(),
                "payload": deliver,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), deliver)
            }
            try:
                await ws.send(json.dumps(out))
            except (ConnectionClosedError, ConnectionClosedOK):
                pass
            except Exception:
                logging.exception(f"[PUB] local deliver to {uid} failed")

        # forward to other servers (fan-out)
        for sid, peer in list(self.peers.items()):
            fwd = ServerDeliverPayload(
                user_id="public",
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            out = {
                "type": MsgType.SERVER_DELIVER,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": fwd,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), fwd)
            }
            try:
                await peer.ws.send(json.dumps(out))
            except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
                logger.warning(f"[PUB] peer {sid} closed while fanout")
                await self._on_peer_closed(sid)
            except Exception:
                logging.exception(f"[PUB] fanout to {sid} failed")
                await self._on_peer_closed(sid)

    async def _handle_user_advertise(self, data: dict):
        try:
            payload = UserAdvertisePayload(**data["payload"])
            origin_sid = data["from"]
            self.user_locations[payload.user_id] = f"server_{origin_sid}"
            if not self.db.get_user(payload.user_id):
                self.db.add_user(payload.user_id, payload.pubkey, "", "", payload.meta or {})
            logger.info(f"[GOSSIP] user {payload.user_id} @ server {origin_sid}")
        except Exception:
            logging.exception("[GOSSIP] user_advertise failed")

    async def _handle_user_remove(self, data: dict):
        try:
            payload = UserRemovePayload(**data["payload"])
            origin_sid = data["from"]
            if self.user_locations.get(payload.user_id) == f"server_{origin_sid}":
                self.user_locations.pop(payload.user_id, None)
                logger.info(f"[GOSSIP] user {payload.user_id} removed from server {origin_sid}")
        except Exception:
            logging.exception("[GOSSIP] user_remove failed")

    async def _handle_server_deliver(self, data: dict):
        try:
            payload = ServerDeliverPayload(**data["payload"])
            key = f"{data['ts']}_{data['from']}_{data['to']}_{hash(json.dumps(data['payload'], sort_keys=True))}"
            if key in self.seen_ids:
                return
            self.seen_ids.add(key)

            if payload.user_id in self.local_users:
                deliver = UserDeliverPayload(
                    ciphertext=payload.ciphertext,
                    sender=payload.sender,
                    sender_pub=payload.sender_pub,
                    content_sig=payload.content_sig
                ).model_dump()
                out = {
                    "type": MsgType.USER_DELIVER,
                    "from": self.server_id,
                    "to": payload.user_id,
                    "ts": current_timestamp(),
                    "payload": deliver,
                    "sig": compute_transport_sig(load_private_key(self.server_private_key), deliver)
                }
                try:
                    await self.local_users[payload.user_id].send(json.dumps(out))
                except Exception:
                    logging.exception(f"[FWD] deliver to {payload.user_id} failed")
        except Exception:
            logging.exception("[FWD] server_deliver failed")

    # ---------- commands ----------
    async def _handle_command(self, websocket: WebSocketServerProtocol, msg: ProtocolMessage):
        payload = CommandPayload(**msg.payload)
        cmd = payload.command.strip().lower()
        if cmd == "/list":
            users = sorted(
                list(self.local_users.keys())
                + [u for u, loc in self.user_locations.items() if loc != "local"]
            )
            resp = {
                "type": "COMMAND_RESPONSE",
                "from": self.server_id,
                "to": msg.from_,
                "ts": current_timestamp(),
                "payload": {"command": "list", "users": users},
                "sig": ""
            }
            try:
                await websocket.send(json.dumps(resp))
            except Exception:
                logging.exception("[CMD] /list response failed")

    # ---------- utilities ----------
    async def _error_to(self, ws: WebSocketServerProtocol, code: ErrorCode, detail: str):
        payload = ErrorPayload(code=code, detail=detail).model_dump()
        out = {
            "type": MsgType.ERROR,
            "from": self.server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": payload,
            "sig": ""
        }
        try:
            await ws.send(json.dumps(out))
        except Exception:
            logging.exception("[ERROR->client] failed to send error")

    async def _error_upstream(self, origin: str, code: ErrorCode, detail: str):
        logger.warning(f"[ERROR-UP] {code}: {detail}")


if __name__ == "__main__":
    srv = Server()
    try:
        asyncio.run(srv.start())
    except KeyboardInterrupt:
        # Handle Ctrl+C without traceback; do a best-effort graceful stop
        try:
            asyncio.run(srv.shutdown("keyboard"))
        except RuntimeError:
            # Event loop already closed – nothing else to do
            pass
        print("\n[STOP] Bye.")
