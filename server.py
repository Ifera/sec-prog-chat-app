import asyncio
import json
import logging
import time
from typing import Dict, Tuple, Optional

from websockets.asyncio.client import connect, ClientConnection
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import (
    ConnectionClosedError,
    ConnectionClosedOK,
    WebSocketException,
)

from base_server import BaseServer
from common import Peer
from config import config
from crypto import load_private_key, compute_transport_sig
from database import Database
from models import (
    MsgType, ErrorCode,
    ProtocolMessage,
    ServerHelloJoinPayload, ServerAnnouncePayload, ServerWelcomePayload, ServerGoodbyePayload,
    UserAdvertisePayload, UserRemovePayload, ServerDeliverPayload, UserHelloPayload, MsgDirectPayload,
    MsgPublicChannelPayload, ErrorPayload,
    UserDeliverPayload, CommandPayload,
    current_timestamp, generate_uuid, ServerType
)


class Server(BaseServer):

    def __init__(self):
        super().__init__(
            server_type=ServerType.SERVER,
            logger=logging.getLogger("Server"),
            ping_interval=5,
            ping_timeout=5
        )
        self.db = Database(config.db_path)

        # remote servers
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # sid -> (host, port)

        # local presence + routing (user clients)
        self.local_users: Dict[str, ServerConnection] = {}  # user_id -> ws
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_{sid}"

        # connection roles (server vs user) for incoming sockets
        self.connection_roles: Dict[ServerConnection, str] = {}  # ws -> "server" | "user"

        # duplicate suppression for forwarded deliveries
        self.seen_ids: set[str] = set()

        # reconnection serialization per sid
        self._reconnect_locks: Dict[str, asyncio.Lock] = {}  # sid -> lock

    async def on_start(self):
        self._bg_tasks.add(asyncio.create_task(self.bootstrap_to_network(), name="bootstrap"))

    async def on_shutdown(self, reason: str):
        await self._broadcast_goodbye(reason=reason)

    async def on_shutdown_cleanup(self):
        # close local user sockets
        for uid, ws in list(self.local_users.items()):
            try:
                await ws.close()
            except Exception:
                self.logger.error(f"[CLOSE] closing user {uid} failed")

        self.local_users.clear()
        self.connection_roles.clear()

    # ---------- bootstrap & linking ----------
    async def bootstrap_to_network(self):
        self.logger.info("[BOOTSTRAP] Starting bootstrap to introducers...")
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
                        self.logger.info(f"[BOOTSTRAP] Sent SERVER_HELLO_JOIN to {uri}")

                        raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
                        data = json.loads(raw)
                        if data.get("type") != MsgType.SERVER_WELCOME:
                            self.logger.warning(f"[BOOTSTRAP] Unexpected response: {data.get('type')}")
                            continue

                        welcome = ServerWelcomePayload(**data["payload"])
                        self.server_id = welcome.assigned_id
                        self.logger.info(f"[BOOTSTRAP] Assigned ID: {self.server_id}")

                        for si in welcome.servers:
                            await self._connect_to_server(si.server_id, si.host, int(si.port), si.pubkey)

                        await self._broadcast_announce()
                        self.logger.info("[BOOTSTRAP] Completed.")
                        return
                except (asyncio.TimeoutError, ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
                    self.logger.warning(f"[BOOTSTRAP] {uri} failed: {e!r}")
                except Exception:
                    self.logger.error(f"[BOOTSTRAP] {uri} unexpected error")

            self.logger.info(f"[BOOTSTRAP] Retry in {backoff}s (attempt {attempt}/5)")
            await asyncio.sleep(backoff)
            backoff *= 2

        self.logger.warning("[BOOTSTRAP] All introducers unreachable; operating standalone for now.")

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
            self.logger.info(f"[LINK] Connected to {sid} @ {host}:{port}")
        except (ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
            self.logger.error(f"[LINK] Failed to connect {uri}: {e!r}")
            self._forget_peer(sid)
        except Exception:
            self.logger.error(f"[LINK] Failed to connect {uri}")
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
                self.logger.info(f"[RECONNECT] dialing {sid} @ {host}:{port}")
                await self._connect_to_server(sid, host, int(port), pubkey=None)

                await self._await_peer_entry(sid, timeout=1.0)
                # tiny settle to let remote process SERVER_ANNOUNCE
                await asyncio.sleep(0.1)

                ok = sid in self.peers
                if ok:
                    self.logger.info(f"[RECONNECT] {sid} restored")
                else:
                    self.logger.warning(f"[RECONNECT] {sid} still absent")
                return ok
            except Exception:
                self.logger.error(f"[RECONNECT] failed for {sid}")
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
                    self.logger.error(f"[SEND-RETRY] retry send to {sid} failed after reconnect")
                    return False
            # couldn't reconnect
            self.logger.warning(f"[SEND-RETRY] {sid} unreachable; dropping message")
            return False
        except Exception:
            self.logger.error(f"[SEND] send to {sid} failed")
            return False

    # ---------- peer close ----------
    def _forget_peer(self, sid: str):
        self.peers.pop(sid, None)
        # keep server_addrs to allow reconnect attempts later

    # ---------- incoming handling ----------
    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: dict):
        if req_type in {
            MsgType.SERVER_HELLO_JOIN, MsgType.SERVER_ANNOUNCE,
            MsgType.SERVER_GOODBYE, MsgType.SERVER_WELCOME,
            MsgType.USER_ADVERTISE, MsgType.USER_REMOVE,
            MsgType.SERVER_DELIVER, MsgType.HEARTBEAT, MsgType.ACK
        }:
            self.connection_roles[websocket] = "server"
            self.logger.info(f"[INCOMING(server)] {data}")
        else:
            self.connection_roles[websocket] = "user"
            self.logger.info(f"[INCOMING(user)] {data}")

        if req_type == MsgType.SERVER_HELLO_JOIN:
            await self._handle_server_join(websocket, data)
            return
        if req_type == MsgType.SERVER_ANNOUNCE:
            await self._handle_server_announce(websocket, data)
            return
        if req_type == MsgType.SERVER_GOODBYE:
            await self._handle_server_goodbye(data)
            await websocket.close()
            return

        # treat as user connection
        await self._handle_user_connection(websocket, data)

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
            self.logger.error("[JOIN] failed to handle server join")

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
            self.logger.error("[ANNOUNCE] failed")

    async def _handle_server_goodbye(self, data: dict):
        try:
            sid = data.get("from")
            await self._on_peer_closed(sid)
        except Exception:
            self.logger.error("[GOODBYE] failed")

    async def _listen_server(self, peer: Peer):
        sid = peer.sid
        try:
            async for raw in peer.ws:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    self.logger.error(f"[LISTEN {sid}] invalid JSON")
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
                        self.logger.debug(f"[LISTEN {sid}] unknown type: {mtype}")
                except Exception:
                    self.logger.error(f"[LISTEN {sid}] handler error")
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            self.logger.info(f"[LISTEN {sid}] connection closed: {e!r}")
            await self._on_peer_closed(sid)
        except WebSocketException as e:
            self.logger.warning(f"[LISTEN {sid}] websocket error: {e!r}")
        except Exception:
            self.logger.error(f"[LISTEN {sid}] unexpected failure")

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
                    self.logger.error("[USER] invalid JSON")
                    continue
                if data.get("type") == MsgType.USER_HELLO:
                    user_id = data.get("from")
                await self._process_user_message(websocket, data)
        except (ConnectionClosedOK, ConnectionClosedError):
            pass
        except Exception:
            self.logger.error("[USER] error")
        finally:
            # On disconnect: remove local user and inform peers/locals
            if user_id and self.local_users.pop(user_id, None):
                self.user_locations.pop(user_id, None)
                await self._broadcast_user_remove(user_id)
                await self._broadcast_local_user_remove(user_id)
                self.logger.info(f"[USER] disconnected: {user_id}")

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
                self.logger.error(f"[ROSTER] failed to send local user {uid}")

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
                self.logger.error(f"[ROSTER] failed to send remote user {uid}")

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
                self.logger.error("[LOCAL-REMOVE] failed to send to client")

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
                self.logger.error("[LOCAL-ADV] failed to send to client")

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
                self.logger.error(f"[DM] failed to deliver to local user {target}")
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

        self.logger.warning(f"[ERROR-UP] {ErrorCode.USER_NOT_FOUND}: {target} not registered")

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
                self.logger.error(f"[PUB] local deliver to {uid} failed")

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
            self.logger.info(f"[GOSSIP] user {payload.user_id} @ server {origin_sid}")
        except Exception:
            self.logger.error("[GOSSIP] user_advertise failed")

    async def _handle_user_remove(self, data: dict):
        try:
            payload = UserRemovePayload(**data["payload"])
            origin_sid = data["from"]
            if self.user_locations.get(payload.user_id) == f"server_{origin_sid}":
                self.user_locations.pop(payload.user_id, None)
                self.logger.info(f"[GOSSIP] user {payload.user_id} removed from server {origin_sid}")
        except Exception:
            self.logger.error("[GOSSIP] user_remove failed")

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
                    self.logger.error(f"[FWD] deliver to {payload.user_id} failed")
        except Exception:
            self.logger.error("[FWD] server_deliver failed")

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
                self.logger.error("[CMD] /list response failed")

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
            self.logger.error("[ERROR->client] failed to send error")


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
