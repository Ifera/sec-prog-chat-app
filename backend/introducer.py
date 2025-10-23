# Group 59
# ----------------------------------
# Muhammad Tayyab Rashid - a1988298
# Nguyen Duc Tung Bui - a1976012
# Guilin Luo - a1989840
# Mazharul Islam Rakib - a1990942
# Masud Ahammad - a1993200

import asyncio
import logging
from typing import Dict

from websockets.asyncio.server import ServerConnection

from base_server import BaseServer
from common import Peer, create_body
from crypto import load_private_key, compute_transport_sig
from models import (
    MsgType, ServerHelloJoinPayload, ServerWelcomePayload, ServerInfo,
    generate_uuid, ServerType, ClientInfo, UserAdvertisePayload, ProtocolMessage, UserRemovePayload
)


class Introducer(BaseServer):

    def __init__(self):
        super().__init__(
            server_type=ServerType.INTRODUCER,
            logger=logging.getLogger("Introducer"),
            ping_interval=None,
            ping_timeout=None
        )

        # introducer directory
        self.known_servers: Dict[str, Dict[str, str | int]] = {}  # sid -> {host, port, pubkey}
        self.known_users: Dict[str, Dict[str, str | int]] = {}  # uid -> {host, port, pubkey, server_id}

    async def on_start(self):
        self.logger.info("[BOOTSTRAP] Acting as introducer; awaiting joins.")

    # ---------- peer close ----------
    async def on_peer_closed(self, sid: str):
        if sid in self.known_servers:
            self.known_servers.pop(sid, None)
            server_users = []
            for uid, user_info in self.known_users.items():
                if user_info["server_id"] == sid:
                    server_users.append(uid)
            for uid in server_users:
                self.logger.info(f"[INTRODUCER] Removing user {uid} from known users as server {sid} disconnected")
                self.known_users.pop(uid, None)

    # ---------- incoming handling ----------
    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: ProtocolMessage):
        match req_type:
            case MsgType.SERVER_HELLO_JOIN:
                await self._handle_server_join(websocket, data)
            case MsgType.HEARTBEAT:
                pass
            case MsgType.USER_ADVERTISE:
                await self._handle_user_advertise(websocket, data)
            case MsgType.USER_REMOVE:
                await self._handle_user_remove(websocket, data)
            case _:
                self.logger.error(f"[INCOMING] unknown request type: {req_type}. Skipping...")

    async def _handle_server_join(self, websocket: ServerConnection, data: ProtocolMessage):
        try:
            # SERVER sends SERVER_HELLO_JOIN to INTRODUCER
            payload = ServerHelloJoinPayload(**data.payload)
            requested_id = data.from_ or generate_uuid()
            assigned_id = requested_id if requested_id not in self.known_servers else generate_uuid()
            self.known_servers[assigned_id] = {"host": payload.host, "port": payload.port, "pubkey": payload.pubkey}

            servers_payload = []
            for sid, s in self.known_servers.items():
                if sid == assigned_id:
                    continue
                servers_payload.append(
                    ServerInfo(server_id=sid, host=s["host"], port=int(s["port"]), pubkey=s["pubkey"]).model_dump()
                )

            clients_payload = []
            for uid, u in self.known_users.items():
                if not u:
                    continue
                clients_payload.append(
                    ClientInfo(user_id=uid, host=u["host"], port=int(u["port"]), pubkey=u["pubkey"], server_id=u["server_id"]).model_dump()
                )

            # INTRODUCER responds with SERVER_WELCOME
            welcome_pl = ServerWelcomePayload(assigned_id=assigned_id, servers=servers_payload,
                                              clients=clients_payload).model_dump()
            sig = compute_transport_sig(load_private_key(self.server_private_key), welcome_pl)
            req = create_body(MsgType.SERVER_WELCOME, self.server_id, data.from_, welcome_pl, sig)
            self.logger.info(f"[JOIN] Sending welcome to {assigned_id} @ {payload.host}:{payload.port}")
            await websocket.send(req)

            self.logger.info(f"[JOIN] Registered new server {assigned_id} @ {payload.host}:{payload.port}")

            # register peer socket under the joining server's (claimed) id
            self.peers[assigned_id] = Peer(sid=assigned_id, ws=websocket, host=payload.host, port=payload.port)
        except Exception as e:
            self.logger.error(f"[JOIN] failed to handle server join: {e!r}")

    async def _handle_user_advertise(self, websocket: ServerConnection, data: ProtocolMessage):
        try:
            payload = UserAdvertisePayload(**data.payload)
            host, port = websocket.local_address
            self.known_users[payload.user_id] = {"host": host, "port": port, "pubkey": payload.pubkey, "server_id": payload.server_id}
            self.logger.info(f"[USER ADVERTISE] User {payload.user_id} @ {host}:{port} from server {payload.server_id}")
        except Exception as e:
            self.logger.error(f"[USER ADVERTISE] failed to handle user advertise: {e!r}")

    async def _handle_user_remove(self, websocket: ServerConnection, data: ProtocolMessage):
        try:
            payload = UserRemovePayload(**data.payload)
            if payload.user_id in self.known_users:
                self.known_users.pop(payload.user_id, None)
                self.logger.info(f"[USER REMOVE] {payload.user_id} removed (server={payload.server_id})")
        except Exception as e:
            self.logger.error(f"[USER REMOVE] failed: {e!r}")


if __name__ == "__main__":
    srv = Introducer()
    try:
        asyncio.run(srv.start())
    except KeyboardInterrupt:
        try:
            asyncio.run(srv.shutdown("keyboard"))
        except RuntimeError:
            pass
        print("\n[STOP] Bye")
