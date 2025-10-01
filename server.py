import asyncio
import json
import logging
import time
from typing import Dict, Tuple, Optional

from websockets.asyncio.client import connect, ClientConnection
from websockets.asyncio.server import serve, ServerConnection
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
    WebSocketException,
)

from common import Peer
from config import config
from crypto import generate_rsa_keypair, load_private_key, compute_transport_sig
from database import Database
from models import (
    MsgType, ErrorCode,
    ProtocolMessage,
    ServerHelloJoinPayload, ServerAnnouncePayload, ServerWelcomePayload, ServerGoodbyePayload,
    UserAdvertisePayload, UserRemovePayload, ServerDeliverPayload, HeartbeatPayload,
    UserHelloPayload, MsgDirectPayload, MsgPublicChannelPayload, ErrorPayload,
    UserDeliverPayload, CommandPayload,
    current_timestamp, generate_uuid, ServerType
)

logging.basicConfig(level=config.logging_level, format=config.logging_format)
logger = logging.getLogger("Server")


async def _error_upstream(origin: str, code: ErrorCode, detail: str):
    logger.warning(f"[ERROR-UP] {code}: {detail}")


class Server:

    def __init__(self):
        self.server_id: Optional[str] = None
        self.server_private_key: Optional[str] = None
        self.server_public_key: Optional[str] = None

        self.db = Database(config.db_path)

        # remote servers
        self.peers: Dict[str, Peer] = {}  # sid -> Peer
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # sid -> (host, port)

        # local presence + routing (user clients)
        self.local_users: Dict[str, ServerConnection] = {}  # user_id -> ws
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_{sid}"

        # connection roles (server vs user) for incoming sockets
        self.connection_roles: Dict[ServerConnection, str] = {}  # ws -> "server" | "user"

        # duplicate suppression for forwarded deliveries
        self.seen_ids: set[str] = set()

        # shutdown controls
        self._stop_evt = asyncio.Event()
        self._bg_tasks: set[asyncio.Task] = set()

        # reconnection serialization per sid
        self._reconnect_locks: Dict[str, asyncio.Lock] = {}  # sid -> lock

    # ---------- lifecycle ----------
    def init_server(self):
        self.server_id = generate_uuid()
        self.server_private_key, self.server_public_key = generate_rsa_keypair()
        logger.info(f"[BOOT] Server ID: {self.server_id} @ {config.host}:{config.port}")

    async def start(self):
        self.init_server()

        # background tasks
        self._bg_tasks.add(asyncio.create_task(self.bootstrap_to_network(), name="bootstrap"))
        self._bg_tasks.add(asyncio.create_task(self._health_monitor(), name="health-monitor"))

        async with serve(self._incoming, config.host, config.port, ping_interval=None, ping_timeout=None):
            logger.info(f"[LISTEN] ws://{config.host}:{config.port}/ws")
            try:
                await self._stop_evt.wait()
            except asyncio.CancelledError:
                pass
            finally:
                await self._shutdown_cleanup()

    async def shutdown(self, reason: str = "shutdown"):
        if not self._stop_evt.is_set():
            logger.info("[STOP] Shutting down…")
            await self._broadcast_goodbye(reason=reason)
            self._stop_evt.set()

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
                logging.exception(f"[CLOSE] closing peer {sid} failed")
        self.peers.clear()
        # keep server_addrs (harmless)

        # close local user sockets
        for uid, ws in list(self.local_users.items()):
            try:
                await ws.close()
            except Exception:
                logging.exception(f"[CLOSE] closing user {uid} failed")
        self.local_users.clear()
        self.connection_roles.clear()

        logger.info("[STOP] Clean exit.")

    # ---------- bootstrap & linking ----------
    async def bootstrap_to_network(self):
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
                        self.server_id = welcome.assigned_id
                        logger.info(f"[BOOTSTRAP] Assigned ID: {self.server_id}")

                        for si in welcome.servers:
                            await self._connect_to_server(si.server_id, si.host, int(si.port), si.pubkey)

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
            ws: ClientConnection = await connect(uri)
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
        for sid in list(self.peers.keys()):
            msg = {
                "type": MsgType.SERVER_ANNOUNCE,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": payload,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
            }
            await self._send_with_retry(sid, msg)

    async def _broadcast_goodbye(self, reason: str = "shutdown"):
        payload = ServerGoodbyePayload(reason=reason).model_dump()
        for sid in list(self.peers.keys()):
            msg = {
                "type": MsgType.SERVER_GOODBYE,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": payload,
                "sig": "",
            }
            # best-effort; don't reconnect on goodbye
            try:
                peer = self.peers.get(sid)
                if peer:
                    await peer.ws.send(json.dumps(msg))
            except Exception:
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
                    "payload": HeartbeatPayload(server_type=ServerType.SERVER).model_dump(),
                    "sig": "",
                }
                await asyncio.wait_for(conn.send(json.dumps(hb)), timeout=3)
                return True
        except Exception:
            logging.error(f"[PROBE] failed to {sid} @ {host}:{port}")
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

                try:
                    probe_ok = await self._probe_peer(sid, host, port)
                    now = time.time()

                    if probe_ok:
                        peer.last_seen = now
                        peer.missed = 0
                    else:
                        peer.missed += 1
                        logger.warning(f"[HEALTH] probe failed for {sid} (missed={peer.missed})")

                        quiet = now - peer.last_seen
                        if quiet > timeout_s or peer.missed >= 2:
                            logger.warning(
                                f"[HEALTH] {sid} timed out (quiet={quiet:.1f}s, missed={peer.missed}); removing")
                            await self._on_peer_closed(sid, timed_out=True)
                            continue

                except Exception:
                    logging.exception(f"[HEALTH] unexpected error while probing {sid}")
                    peer.missed += 1
                    if peer.missed >= 2:
                        await self._on_peer_closed(sid, timed_out=True)

            elapsed = time.time() - start
            await asyncio.sleep(max(0.0, hb_interval - elapsed))

    # ---------- reconnect & retry ----------
    async def _await_peer_entry(self, sid: str, timeout: float = 1.0) -> bool:
        """
        Wait up to `timeout` for a reconnected peer entry to appear.
        We don't rely on any `.closed` attribute (not provided by asyncio API).
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.05, timeout)
        while loop.time() < deadline:
            if sid in self.peers:
                return True
            await asyncio.sleep(0.05)
        return False

    async def _reconnect_peer(self, sid: str) -> bool:
        """
        Re-establish a server peer connection using self.server_addrs[sid].
        Serialized per-sid to avoid races. Returns True if the peer entry exists after connect.
        """
        addr = self.server_addrs.get(sid)
        if not addr:
            return False

        lock = self._reconnect_locks.setdefault(sid, asyncio.Lock())
        async with lock:
            if sid in self.peers:
                return True

            host, port = addr
            try:
                logger.info(f"[RECONNECT] dialing {sid} @ {host}:{port}")
                await self._connect_to_server(sid, host, int(port), pubkey=None)

                await self._await_peer_entry(sid, timeout=1.0)
                # tiny settle to let remote process SERVER_ANNOUNCE
                await asyncio.sleep(0.1)

                ok = sid in self.peers
                if ok:
                    logger.info(f"[RECONNECT] {sid} restored")
                else:
                    logger.warning(f"[RECONNECT] {sid} still absent")
                return ok
            except Exception:
                logging.exception(f"[RECONNECT] failed for {sid}")
                return False

    async def _send_with_retry(self, sid: str, msg: dict) -> bool:
        """
        Send `msg` to peer `sid`. If the first send fails due to a websocket issue,
        try a single reconnect and re-send. Returns True if sent.
        """
        # First attempt
        try:
            peer = self.peers.get(sid)
            if not peer:
                return False
            await peer.ws.send(json.dumps(msg))
            return True
        except (ConnectionClosedError, ConnectionClosedOK, WebSocketException):
            # try to reconnect and retry once
            if await self._reconnect_peer(sid):
                try:
                    peer2 = self.peers.get(sid)
                    if not peer2:
                        return False
                    await peer2.ws.send(json.dumps(msg))
                    return True
                except (ConnectionClosedOK, ConnectionClosedError, WebSocketException):
                    # remote closed immediately after reconnect; prune silently
                    await self._on_peer_closed(sid)
                    return False
                except Exception:
                    logging.exception(f"[SEND-RETRY] retry send to {sid} failed after reconnect")
                    return False
            # couldn't reconnect
            logger.warning(f"[SEND-RETRY] {sid} unreachable; dropping message")
            return False
        except Exception:
            logging.exception(f"[SEND] send to {sid} failed")
            return False

    # ---------- peer close ----------
    async def _on_peer_closed(self, sid: str, timed_out: bool = False):
        """Cleanup when a *server* peer is closed or unhealthy."""
        peer = self.peers.pop(sid, None)

        # keep self.server_addrs[sid] so we can still reconnect later

        if peer:
            try:
                await peer.ws.close()
            except Exception:
                logging.exception(f"[CLOSE] peer close {sid} failed")

    def _forget_peer(self, sid: str):
        self.peers.pop(sid, None)
        # keep server_addrs to allow reconnect attempts later

    # ---------- incoming handling ----------
    async def _incoming(self, websocket: ServerConnection):
        """
        Differentiate *server peer* vs *user client* by inspecting the first frame.
        Also record the role for this connection.
        """
        try:
            first_raw = await websocket.recv()
            first = json.loads(first_raw)
            ftype = first.get("type")

            # Decide role
            if ftype in {
                MsgType.SERVER_HELLO_JOIN, MsgType.SERVER_ANNOUNCE,
                MsgType.SERVER_GOODBYE, MsgType.SERVER_WELCOME,
                MsgType.USER_ADVERTISE, MsgType.USER_REMOVE,
                MsgType.SERVER_DELIVER, MsgType.HEARTBEAT, MsgType.ACK
            }:
                self.connection_roles[websocket] = "server"
                logger.info(f"[INCOMING(server)] {first}")
            else:
                self.connection_roles[websocket] = "user"
                logger.info(f"[INCOMING(user)] {first}")

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
                # allowed; fall through
                pass

            # treat as user connection
            await self._handle_user_connection(websocket, first)

        except (ConnectionClosedError, ConnectionClosedOK):
            pass
        except json.JSONDecodeError:
            logging.exception("[INCOMING] invalid JSON on first frame")
        except Exception:
            logging.exception("[INCOMING] error in first frame handling")

    async def _handle_server_join(self, websocket: ServerConnection, data: dict):
        try:
            payload = ServerHelloJoinPayload(**data["payload"])
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

    async def _handle_server_announce(self, websocket: ServerConnection, data: dict):
        try:
            payload = ServerAnnouncePayload(**data["payload"])
            sid = data["from"]

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
                        pass
                    else:
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
    async def _handle_user_connection(self, websocket: ServerConnection, first: dict):
        user_id: Optional[str] = None
        try:
            await self._process_user_message(websocket, first)
            if first.get("type") == MsgType.USER_HELLO:
                user_id = first.get("from")

            async for raw in websocket:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    logging.exception("[USER] invalid JSON")
                    continue
                if data.get("type") == MsgType.USER_HELLO:
                    user_id = data.get("from")
                await self._process_user_message(websocket, data)
        except (ConnectionClosedOK, ConnectionClosedError):
            pass
        except Exception:
            logging.exception("[USER] error")
        finally:
            # On disconnect: remove local user and inform peers/locals
            if user_id and self.local_users.pop(user_id, None):
                self.user_locations.pop(user_id, None)
                await self._broadcast_user_remove(user_id)
                await self._broadcast_local_user_remove(user_id)
                logger.info(f"[USER] disconnected: {user_id}")

    async def _process_user_message(self, websocket: ServerConnection, data: dict):
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
            pass
        else:
            await self._error_to(ws=websocket, code=ErrorCode.UNKNOWN_TYPE, detail=f"Unknown type {msg.type}")

    async def _user_hello(self, websocket: ServerConnection, msg: ProtocolMessage):
        """
        Register the user, then (crucially) send the existing roster so the new user
        knows about earlier users (fixes Bob not seeing Alice).
        """
        payload = UserHelloPayload(**msg.payload)
        user_id = msg.from_
        if user_id in self.local_users:
            await self._error_to(ws=websocket, code=ErrorCode.NAME_IN_USE, detail="User ID already in use")
            return

        self.local_users[user_id] = websocket
        self.user_locations[user_id] = "local"
        self.db.add_user(user_id, payload.pubkey, "", "", {})

        # 1) Send existing roster (local + remote) to the NEW user
        await self._send_roster_to_user(websocket, exclude_user=user_id)

        # 2) Gossip advertise to other servers
        await self._gossip_user_advertise(user_id, payload.pubkey)

        # 3) Tell all local users (including the new one) about this new user
        await self._broadcast_local_user_advertise(user_id, payload.pubkey)

    async def _send_roster_to_user(self, websocket: ServerConnection, exclude_user: Optional[str] = None):
        """
        Send USER_ADVERTISE for all known users (local + remote) to a single websocket.
        This ensures a newly joined user learns about earlier users' pubkeys.
        """
        # Local users first
        for uid in list(self.local_users.keys()):
            if uid == exclude_user:
                continue
            rec = self.db.get_user(uid)
            if not rec:
                continue
            advertise = {
                "type": MsgType.USER_ADVERTISE,
                "from": self.server_id,
                "to": "*",
                "ts": current_timestamp(),
                "payload": {
                    "user_id": uid,
                    "server_id": self.server_id,
                    "pubkey": rec["pubkey"],
                    "meta": {}
                },
                "sig": ""
            }
            try:
                await websocket.send(json.dumps(advertise))
            except Exception:
                logging.exception(f"[ROSTER] failed to send local user {uid}")

        # Remote users (learned via gossip)
        for uid, loc in list(self.user_locations.items()):
            if loc == "local" or uid == exclude_user:
                continue
            rec = self.db.get_user(uid)
            if not rec:
                continue
            try:
                server_id = loc.split("_", 1)[1]
            except Exception:
                server_id = "unknown"

            advertise = {
                "type": MsgType.USER_ADVERTISE,
                "from": self.server_id,
                "to": "*",
                "ts": current_timestamp(),
                "payload": {
                    "user_id": uid,
                    "server_id": server_id,
                    "pubkey": rec["pubkey"],
                    "meta": {}
                },
                "sig": ""
            }
            try:
                await websocket.send(json.dumps(advertise))
            except Exception:
                logging.exception(f"[ROSTER] failed to send remote user {uid}")

    async def _broadcast_user_remove(self, user_id: str):
        """Inform remote servers that a local user has gone away."""
        payload = UserRemovePayload(user_id=user_id, server_id=self.server_id).model_dump()
        for sid in list(self.peers.keys()):
            msg = {
                "type": MsgType.USER_REMOVE,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": payload,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
            }
            await self._send_with_retry(sid, msg)

    async def _broadcast_local_user_remove(self, user_id: str):
        """Tell local clients a user has gone (optional UX consistency)."""
        remove = {
            "type": MsgType.USER_REMOVE,
            "from": self.server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": {
                "user_id": user_id,
                "server_id": self.server_id
            },
            "sig": ""
        }
        for _, ws in list(self.local_users.items()):
            try:
                await ws.send(json.dumps(remove))
            except (ConnectionClosedError, ConnectionClosedOK):
                pass
            except Exception:
                logging.exception("[LOCAL-REMOVE] failed to send to client")

    async def _gossip_user_advertise(self, user_id: str, pubkey: str):
        payload = UserAdvertisePayload(user_id=user_id, server_id=self.server_id, pubkey=pubkey, meta={}).model_dump()
        for sid in list(self.peers.keys()):
            msg = {
                "type": MsgType.USER_ADVERTISE,
                "from": self.server_id,
                "to": sid,
                "ts": current_timestamp(),
                "payload": payload,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), payload),
            }
            await self._send_with_retry(sid, msg)

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
            await self._send_with_retry(sid, out)
            return

        await _error_upstream(origin=msg.from_, code=ErrorCode.USER_NOT_FOUND, detail=f"{target} not registered")

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
        for sid in list(self.peers.keys()):
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
            await self._send_with_retry(sid, out)

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
    async def _handle_command(self, websocket: ServerConnection, msg: ProtocolMessage):
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
    async def _error_to(self, ws: ServerConnection, code: ErrorCode, detail: str):
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


if __name__ == "__main__":
    srv = Server()
    try:
        asyncio.run(srv.start())
    except KeyboardInterrupt:
        try:
            asyncio.run(srv.shutdown("keyboard"))
        except RuntimeError:
            pass
        print("\n[STOP] Bye.")
