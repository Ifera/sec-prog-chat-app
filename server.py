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
    current_timestamp, ServerType
)


class Server(BaseServer):

    def __init__(self):
        super().__init__(
            server_type=ServerType.SERVER,
            logger=logging.getLogger("Server"),
            ping_interval=15,
            ping_timeout=45
        )
        self.db = Database(config.db_path)
        self.introducer_ws: ClientConnection | None = None

        # remote servers
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # sid -> (host, port)

        # local presence + routing (user clients)
        self.local_users: Dict[str, ServerConnection] = {}  # user_id -> ws
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_{sid}"

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
            except Exception as e:
                self.logger.error(f"[CLOSE] closing user {uid} failed: {e!r}")

        self.local_users.clear()

    # executed on startup - connect with an introducer and link with servers and get a list of connected clients
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
                    async for ws in connect(uri, logger=self.logger):
                        # send SERVER_HELLO_JOIN to introducer
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
                        self.logger.info(f"[BOOTSTRAP] Sent SERVER_HELLO_JOIN to Introducer at {uri}")

                        # receive SERVER_WELCOME from introducer
                        raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
                        raw_json = json.loads(raw)
                        data = ProtocolMessage(**raw_json)
                        if data.type != MsgType.SERVER_WELCOME:
                            self.logger.warning(
                                f"[BOOTSTRAP] Unexpected response: {data.get('type')} was expecting SERVER_WELCOME from Introducer")
                            continue

                        welcome = ServerWelcomePayload(**data.payload)
                        self.server_id = welcome.assigned_id
                        self.introducer_ws = ws
                        self.logger.info(f"[BOOTSTRAP] Assigned ID: {self.server_id}")
                        self.logger.info("[BOOTSTRAP] Introducer connection successful")

                        # connect to other servers on the network by sending SERVER_ANNOUNCE
                        remote_servers_cnt = len(welcome.servers)
                        if remote_servers_cnt > 0:
                            self.logger.info(f"[BOOTSTRAP] Connecting to remote servers ({remote_servers_cnt} found)...")
                        else:
                            self.logger.info("[BOOTSTRAP] No remote servers found...")

                        for si in welcome.servers:
                            await self._connect_to_server(si.server_id, si.host, int(si.port), si.pubkey)

                        # maintain a list of clients connected already
                        for ci in welcome.clients:
                            # TODO: handle clients from introducer
                            pass

                        # wait for this connection to close
                        await ws.wait_closed()

                        # when we get here, the async-for will attempt a reconnect
                except (asyncio.TimeoutError, ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
                    self.logger.warning(f"[BOOTSTRAP] {uri} failed: {e!r}")
                except Exception as e:
                    self.logger.error(f"[BOOTSTRAP] {uri} unexpected error: {e!r}")

            self.logger.info(f"[BOOTSTRAP] Retry in {backoff}s (attempt {attempt}/5)")
            await asyncio.sleep(backoff)
            backoff *= 2

        self.logger.warning("[BOOTSTRAP] All introducers unreachable; operating standalone for now.")

    async def _connect_to_server(self, sid: str, host: str, port: int, pubkey: Optional[str]):
        """Create a persistent websocket to another server and send SERVER_ANNOUNCE during STARTUP or RECONNECT"""
        uri = f"ws://{host}:{port}/ws"
        try:
            # connect to the remote server
            ws: ClientConnection = await connect(uri, ping_interval=5, ping_timeout=10)  # TODO: check
            peer = Peer(sid=sid, ws=ws, host=host, port=port, pubkey=pubkey)
            self.peers[sid] = peer
            self.server_addrs[sid] = (host, port)

            # send SERVER_ANNOUNCE to the remote server
            payload = ServerAnnouncePayload(
                host=config.host,
                port=config.port,
                pubkey=self.server_public_key,
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

            # start listener for that server
            self._bg_tasks.add(asyncio.create_task(self._listen_server(peer), name=f"listen-{sid}"))
            self.logger.info(f"[LINK] Connected to {sid} @ {host}:{port}")
        except (ConnectionClosedError, ConnectionClosedOK, WebSocketException) as e:
            self.logger.error(f"[LINK] Failed to connect {uri}: {e!r}")
            self._forget_peer(sid)
        except Exception as e:
            self.logger.error(f"[LINK] Failed to connect {uri}: {e!r}")
            self._forget_peer(sid)

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
            except Exception as e:
                self.logger.error(f"[RECONNECT] failed for {sid}: {e!r}")
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
                except Exception as e:
                    self.logger.error(f"[SEND-RETRY] retry send to {sid} failed after reconnect: {e!r}")
                    return False
            # couldn't reconnect
            self.logger.warning(f"[SEND-RETRY] {sid} unreachable; dropping message")
            return False
        except Exception as e:
            self.logger.error(f"[SEND] send to {sid} failed: {e!r}")
            return False

    # ---------- peer close ----------
    def _forget_peer(self, sid: str):
        self.peers.pop(sid, None)
        # keep server_addrs to allow reconnect attempts later

    # ---------- incoming handling ----------
    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        if req_type != MsgType.HEARTBEAT:
            self.logger.info(f"[INCOMING] Request: {data}")

        match req_type:
            case MsgType.SERVER_ANNOUNCE:
                await self._handle_server_announce(websocket, data)
            case MsgType.SERVER_GOODBYE:
                await self._handle_server_goodbye(data)
                await websocket.close()
            case _:
                # assume user message
                await self._handle_user_connection(websocket, req_type, data)

    async def _handle_server_announce(self, websocket: ServerConnection, data: ProtocolMessage):
        try:
            pl = ServerAnnouncePayload(**data.payload)
            sid = data.from_

            if sid in self.peers:
                peer = self.peers[sid]
                peer.ws = websocket
                peer.host = pl.host
                peer.port = pl.port
                peer.pubkey = pl.pubkey
                peer.last_seen = time.time()
                peer.missed = 0
            else:
                self.peers[sid] = Peer(sid=sid, ws=websocket, host=pl.host, port=pl.port, pubkey=pl.pubkey)
                self._bg_tasks.add(asyncio.create_task(self._listen_server(self.peers[sid]), name=f"listen-{sid}"))

            self.server_addrs[sid] = (pl.host, pl.port)
        except Exception as e:
            self.logger.error(f"[ANNOUNCE] failed: {e!r}")

    async def _handle_server_goodbye(self, data: ProtocolMessage):
        try:
            sid = data.from_
            await self._on_peer_closed(sid)
        except Exception as e:
            self.logger.error(f"[GOODBYE] failed: {e!r}")

    async def _listen_server(self, peer: Peer):
        sid = peer.sid
        try:
            async for raw in peer.ws:
                try:
                    raw_json = json.loads(raw)
                except json.JSONDecodeError as e:
                    self.logger.error(f"[LISTEN {sid}] invalid JSON: {e!r}")
                    continue

                pr = self.peers.get(sid)
                if pr:
                    pr.last_seen = time.time()
                    pr.missed = 0

                try:
                    data = ProtocolMessage(**raw_json)
                    req_type = data.type
                    match req_type:
                        case MsgType.USER_ADVERTISE:
                            await self._handle_user_advertise(data)
                        case MsgType.USER_REMOVE:
                            await self._handle_user_remove(data)
                        case MsgType.SERVER_DELIVER:
                            await self._handle_server_deliver(data)
                        case MsgType.SERVER_GOODBYE:
                            await self._handle_server_goodbye(data)
                        case _:
                            self.logger.debug(f"[LISTEN {sid}] unknown type: {req_type}")
                except Exception as e:
                    self.logger.error(f"[LISTEN {sid}] handler error: {e!r}")
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            self.logger.info(f"[LISTEN {sid}] connection closed: {e!r}")
            await self._on_peer_closed(sid)
        except WebSocketException as e:
            self.logger.warning(f"[LISTEN {sid}] websocket error: {e!r}")
        except Exception as e:
            self.logger.error(f"[LISTEN {sid}] unexpected failure: {e!r}")

    # ---------- user side ----------
    async def _handle_user_connection(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        try:
            match req_type:
                case MsgType.USER_HELLO:
                    await self._user_hello(websocket, data)
                case MsgType.MSG_DIRECT:
                    await self._msg_direct(data)
                case MsgType.MSG_PUBLIC_CHANNEL:
                    await self._msg_public(data)
                case MsgType.COMMAND:
                    await self._handle_command(websocket, data)
                case _:
                    self.logger.debug(f"[USER] unknown type: {req_type}")
        except (ConnectionClosedOK, ConnectionClosedError):
            # TODO: maybe remove user on disconnect?
            pass
        except Exception as e:
            self.logger.error(f"[USER] error: {e!r}")

    async def _user_hello(self, websocket: ServerConnection, msg: ProtocolMessage):
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
            except Exception as e:
                self.logger.error(f"[ROSTER] failed to send local user {uid}: {e!r}")

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
            except Exception as e:
                self.logger.error(f"[ROSTER] failed to send remote user {uid}: {e!r}")

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
            except Exception as e:
                self.logger.error(f"[LOCAL-REMOVE] failed to send to client: {e!r}")

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
            except Exception as e:
                self.logger.error(f"[LOCAL-ADV] failed to send to client: {e!r}")

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
            except Exception as e:
                self.logger.error(f"[DM] failed to deliver to local user {target}: {e!r}")
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
            except Exception as e:
                self.logger.error(f"[PUB] local deliver to {uid} failed: {e!r}")

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

    async def _handle_user_advertise(self, data: ProtocolMessage):
        try:
            payload = UserAdvertisePayload(**data.payload)
            origin_sid = data.from_
            self.user_locations[payload.user_id] = f"server_{origin_sid}"
            if not self.db.get_user(payload.user_id):
                self.db.add_user(payload.user_id, payload.pubkey, "", "", payload.meta or {})
            self.logger.info(f"[GOSSIP] user {payload.user_id} @ server {origin_sid}")
        except Exception as e:
            self.logger.error(f"[GOSSIP] user_advertise failed: {e!r}")

    async def _handle_user_remove(self, data: ProtocolMessage):
        try:
            payload = UserRemovePayload(**data.payload)
            origin_sid = data.from_
            if self.user_locations.get(payload.user_id) == f"server_{origin_sid}":
                self.user_locations.pop(payload.user_id, None)
                self.logger.info(f"[GOSSIP] user {payload.user_id} removed from server {origin_sid}")
        except Exception as e:
            self.logger.error(f"[GOSSIP] user_remove failed: {e!r}")

    async def _handle_server_deliver(self, data: ProtocolMessage):
        try:
            payload = ServerDeliverPayload(**data.payload)
            key = f"{data.ts}_{data.from_}_{data.to}_{hash(json.dumps(data.payload, sort_keys=True))}"
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
                except Exception as e:
                    self.logger.error(f"[FWD] deliver to {payload.user_id} failed: {e!r}")
        except Exception as e:
            self.logger.error(f"[FWD] server_deliver failed: {e!r}")

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
            except Exception as e:
                self.logger.error(f"[CMD] /list response failed: {e!r}")

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
        except Exception as e:
            self.logger.error(f"[ERROR->client] failed to send error: {e!r}")


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
