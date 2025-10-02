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
from common import Peer, create_body
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
    ServerType, CommandResponsePayload
)


class Server(BaseServer):

    def __init__(self):
        super().__init__(
            server_type=ServerType.SERVER,
            logger=logging.getLogger("Server"),
            ping_interval=config.heartbeat_interval,
            ping_timeout=config.timeout_threshold
        )
        self.db = Database(config.db_path)
        self.introducer_ws: ClientConnection | None = None

        # remote servers
        self.server_addrs: Dict[str, Tuple[str, int]] = {}  # sid -> (host, port)

        # local presence + routing (user clients)
        self.local_users: Dict[str, ServerConnection] = {}  # user_id -> ws
        self.user_locations: Dict[str, str] = {}  # user_id -> "local" | f"server_id"

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
                        sig = compute_transport_sig(load_private_key(self.server_private_key), payload)
                        req = create_body(MsgType.SERVER_HELLO_JOIN, self.server_id, f"{host}:{port}", payload, sig)
                        await ws.send(req)
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
                            self.logger.info(
                                f"[BOOTSTRAP] Connecting to remote servers ({remote_servers_cnt} found)...")
                        else:
                            self.logger.info("[BOOTSTRAP] No remote servers found...")

                        for si in welcome.servers:
                            await self._connect_to_server(si.server_id, si.host, int(si.port), si.pubkey)

                        # maintain a list of clients connected already
                        remote_clients_cnt = len(welcome.clients)
                        if remote_clients_cnt > 0:
                            self.logger.info(f"[BOOTSTRAP] Got {remote_clients_cnt} remote clients...")
                        else:
                            self.logger.info("[BOOTSTRAP] No remote clients found...")

                        for ci in welcome.clients:
                            self.user_locations[ci.user_id] = ci.server_id

                        self.logger.info("[BOOTSTRAP] Bootstrap complete")

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
        uri = f"ws://{host}:{port}/ws"
        try:
            # connect to the remote server
            ws: ClientConnection = await connect(uri, logger=self.logger)
            peer = Peer(sid=sid, ws=ws, host=host, port=port, pubkey=pubkey, outbound=True)
            self.peers[sid] = peer
            self.server_addrs[sid] = (host, port)

            # send SERVER_ANNOUNCE to the remote server
            payload = ServerAnnouncePayload(
                host=config.host,
                port=config.port,
                pubkey=self.server_public_key,
            ).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), payload)
            req = create_body(MsgType.SERVER_ANNOUNCE, self.server_id, sid, payload, sig)
            await ws.send(req)

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
        for sid, p in self.peers.items():
            req = create_body(MsgType.SERVER_GOODBYE, self.server_id, sid, payload)
            try:
                await p.ws.send(req)
            except Exception:
                pass

    # ---------- peer close ----------
    def _forget_peer(self, sid: str):
        self.peers.pop(sid, None)

    # ---------- incoming handling ----------
    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        await self._handle(websocket, req_type, data)

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
                    await self._handle(pr.ws, data.type, data)
                except Exception as e:
                    self.logger.error(f"[LISTEN {sid}] handler error: {e!r}")
        except (ConnectionClosedError, ConnectionClosedOK) as e:
            self.logger.info(f"[LISTEN {sid}] connection closed: {e!r}")
            await self._on_peer_closed(sid)
        except WebSocketException as e:
            self.logger.warning(f"[LISTEN {sid}] websocket error: {e!r}")
        except Exception as e:
            self.logger.error(f"[LISTEN {sid}] unexpected failure: {e!r}")

    async def _handle(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        if req_type != MsgType.HEARTBEAT:
            self.logger.info(f"[INCOMING] Request: {data}")

        match req_type:
            case MsgType.USER_ADVERTISE:
                await self._handle_user_advertise(data)
            case MsgType.USER_REMOVE:
                await self._handle_user_remove(data)
            case MsgType.SERVER_DELIVER:
                await self._handle_server_deliver(data)
            case MsgType.SERVER_GOODBYE:
                await self._handle_server_goodbye(data)
            case MsgType.SERVER_ANNOUNCE:
                await self._handle_server_announce(websocket, data)
            case MsgType.SERVER_GOODBYE:
                await self._handle_server_goodbye(data)
                await websocket.close()
            case _:  # assume user message
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

            self.server_addrs[sid] = (pl.host, pl.port)
        except Exception as e:
            self.logger.error(f"[ANNOUNCE] failed: {e!r}")

    async def _handle_server_goodbye(self, data: ProtocolMessage):
        try:
            sid = data.from_
            await self._on_peer_closed(sid)
        except Exception as e:
            self.logger.error(f"[GOODBYE] failed: {e!r}")

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
                    self.logger.error(f"[USER] Unknown request type: {req_type}")
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

        # when a new user connects, we first advertise their identity to all other servers/peers and the introducer
        # then we send the existing roster to the new user
        # finally we advertise the new user to all local users (including the new one)

        # gossip advertise to other servers (including the introducer)
        await self._gossip_user_advertise(user_id, payload.pubkey)

        # send the existing roster to the NEW user
        await self._send_roster_to_user(websocket, user_id)

        # tell all local users (including the new one) about this new user
        await self._broadcast_local_user_advertise(user_id, payload.pubkey)

    async def _gossip_user_advertise(self, user_id: str, pubkey: str):
        payload = UserAdvertisePayload(user_id=user_id, server_id=self.server_id, pubkey=pubkey, meta={}).model_dump()
        sig = compute_transport_sig(load_private_key(self.server_private_key), payload)
        req = create_body(MsgType.USER_ADVERTISE, self.server_id, "*", payload, sig)

        # fan-out to all connected servers
        for sid, peer in self.peers.items():
            await peer.ws.send(req)

        # fan-out to the introducer
        if self.introducer_ws:
            await self.introducer_ws.send(req)

    async def _send_roster_to_user(self, websocket: ServerConnection, exclude_user: str):
        """
        Send USER_ADVERTISE for all known LOCAL users to a single websocket.
        This ensures a newly joined user learns about earlier users' pubkeys.
        """
        for uid in list(self.local_users.keys()):
            if uid == exclude_user:
                continue

            rec = self.db.get_user(uid)
            if not rec:
                continue

            payload = UserAdvertisePayload(user_id=uid, server_id=self.server_id, pubkey=rec["pubkey"], meta={}).model_dump()
            req = create_body(MsgType.USER_ADVERTISE, self.server_id, exclude_user, payload)

            try:
                await websocket.send(req)
            except Exception as e:
                self.logger.error(f"[ROSTER] failed sending local user {uid} to {exclude_user}: {e!r}")

            # TODO: send roster of remote users?

    async def _broadcast_local_user_advertise(self, user_id: str, pubkey: str):
        payload = UserAdvertisePayload(user_id=user_id, server_id=self.server_id, pubkey=pubkey, meta={}).model_dump()

        for uid, ws in list(self.local_users.items()):
            req = create_body(MsgType.USER_ADVERTISE, self.server_id, uid, payload)
            try:
                await ws.send(req)
            except (ConnectionClosedError, ConnectionClosedOK):
                pass
            except Exception as e:
                self.logger.error(f"[LOCAL-ADV] failed to send to client: {e!r}")

    async def _msg_direct(self, msg: ProtocolMessage):
        payload = MsgDirectPayload(**msg.payload)
        target = msg.to

        # deliver locally if present
        if target in self.local_users:
            deliver_pl = UserDeliverPayload(
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), deliver_pl)
            req = create_body(MsgType.USER_DELIVER, self.server_id, target, deliver_pl, sig)
            try:
                await self.local_users[target].send(req)
            except Exception as e:
                self.logger.error(f"[DM] failed to deliver to local user {target}: {e!r}")
            return

        # else route to remote server if we know it
        sid = self.user_locations.get(target)
        if sid and sid != "local" and sid in self.peers:
            fwd_pl = ServerDeliverPayload(
                user_id=target,
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), fwd_pl)
            req = create_body(MsgType.SERVER_DELIVER, self.server_id, sid, fwd_pl, sig)
            await self.peers[sid].ws.send(req)
            return

        self.logger.warning(f"[ERROR-UP] {ErrorCode.USER_NOT_FOUND}: {target} not registered")

    async def _msg_public(self, msg: ProtocolMessage):
        payload = MsgPublicChannelPayload(**msg.payload)

        # broadcast to local users
        for uid, ws in list(self.local_users.items()):
            deliver_pl = UserDeliverPayload(
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), deliver_pl)
            req = create_body(MsgType.USER_DELIVER, self.server_id, uid, deliver_pl, sig)
            try:
                await ws.send(req)
            except (ConnectionClosedError, ConnectionClosedOK):
                pass
            except Exception as e:
                self.logger.error(f"[PUB] local deliver to {uid} failed: {e!r}")

        # forward to other servers (fan-out)
        for sid, p in self.peers.items():
            fwd_pl = ServerDeliverPayload(
                user_id="public",
                ciphertext=payload.ciphertext,
                sender=msg.from_,
                sender_pub=payload.sender_pub,
                content_sig=payload.content_sig
            ).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), fwd_pl)
            req = create_body(MsgType.SERVER_DELIVER, self.server_id, sid, fwd_pl, sig)
            await p.ws.send(req)

    async def _handle_user_advertise(self, data: ProtocolMessage):
        try:
            payload = UserAdvertisePayload(**data.payload)
            origin_sid = data.from_
            self.user_locations[payload.user_id] = origin_sid
            if not self.db.get_user(payload.user_id):
                self.db.add_user(payload.user_id, payload.pubkey, "", "", payload.meta or {})
            self.logger.info(f"[GOSSIP] user {payload.user_id} @ server {origin_sid}")
        except Exception as e:
            self.logger.error(f"[GOSSIP] user_advertise failed: {e!r}")

    async def _handle_user_remove(self, data: ProtocolMessage):
        try:
            payload = UserRemovePayload(**data.payload)
            origin_sid = data.from_
            if self.user_locations.get(payload.user_id) == origin_sid:
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
                deliver_pl = UserDeliverPayload(
                    ciphertext=payload.ciphertext,
                    sender=payload.sender,
                    sender_pub=payload.sender_pub,
                    content_sig=payload.content_sig
                ).model_dump()
                sig = compute_transport_sig(load_private_key(self.server_private_key), deliver_pl)
                req = create_body(MsgType.USER_DELIVER, self.server_id, payload.user_id, deliver_pl, sig)
                try:
                    await self.local_users[payload.user_id].send(req)
                except Exception as e:
                    self.logger.error(f"[FWD] deliver to {payload.user_id} failed: {e!r}")
        except Exception as e:
            self.logger.error(f"[FWD] server_deliver failed: {e!r}")

    # ---------- commands ----------
    async def _handle_command(self, websocket: ServerConnection, data: ProtocolMessage):
        payload = CommandPayload(**data.payload)
        cmd = payload.command.strip().lower()
        # TODO: improve command handling
        if cmd == "/list":
            users = sorted(
                list(self.local_users.keys())
                + [u for u, loc in self.user_locations.items() if loc != "local"]
            )
            response = {
                "users": users,
            }
            res_pl = CommandResponsePayload(command=cmd, response=json.dumps(response)).model_dump()
            body = create_body(MsgType.COMMAND_RESPONSE, self.server_id, data.from_, res_pl)
            try:
                await websocket.send(body)
            except Exception as e:
                self.logger.error(f"[CMD] /list response failed: {e!r}")

    # ---------- utilities ----------
    async def _error_to(self, ws: ServerConnection, code: ErrorCode, detail: str):
        payload = ErrorPayload(code=code, detail=detail).model_dump()
        body = create_body(MsgType.ERROR, self.server_id, "*", payload)
        try:
            await ws.send(body)
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
