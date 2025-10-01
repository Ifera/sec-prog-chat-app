import asyncio
import json
import logging
from typing import Dict

from websockets.asyncio.server import ServerConnection

from base_server import BaseServer
from common import Peer
from crypto import load_private_key, compute_transport_sig
from models import (
    MsgType, ServerHelloJoinPayload, ServerWelcomePayload, ServerInfo,
    current_timestamp, generate_uuid, ServerType
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

    async def on_start(self):
        self.logger.info("[BOOTSTRAP] Acting as introducer; awaiting joins.")

    # ---------- peer close ----------
    async def on_peer_closed(self, sid: str):
        if sid in self.known_servers:
            self.known_servers.pop(sid, None)

    # ---------- incoming handling ----------
    async def handle_incoming(self, websocket: ServerConnection, req_type: str, data: dict):
        if req_type == MsgType.SERVER_HELLO_JOIN:
            await self._handle_server_join(websocket, data)
        else:
            self.logger.error(f"[INCOMING] unknown request type: {req_type}")
            await websocket.close()

    async def _handle_server_join(self, websocket: ServerConnection, data: dict):
        try:
            # SERVER sends SERVER_HELLO_JOIN to INTRODUCER
            payload = ServerHelloJoinPayload(**data["payload"])
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

            # INTRODUCER responds with SERVER_WELCOME (including assigned_id and current servers)
            welcome = ServerWelcomePayload(assigned_id=assigned_id, servers=servers_payload).model_dump()
            msg = {
                "type": MsgType.SERVER_WELCOME,
                "from": self.server_id,
                "to": data.get("from"),
                "ts": current_timestamp(),
                "payload": welcome,
                "sig": compute_transport_sig(load_private_key(self.server_private_key), welcome),
            }
            self.logger.info(f"[JOIN] Sending welcome to {assigned_id} @ {payload.host}:{payload.port}")
            await websocket.send(json.dumps(msg))

            self.logger.info(f"[JOIN] Registered new server {assigned_id} @ {payload.host}:{payload.port}")

            # register peer socket under the joining server's (claimed) id
            self.peers[assigned_id] = Peer(sid=assigned_id, ws=websocket, host=payload.host, port=payload.port)
        except Exception:
            self.logger.error("[JOIN] failed to handle server join")


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
