import asyncio
import json
import logging
import os
import sys
from typing import Dict, Optional, Union

from websockets.asyncio.client import connect, ClientConnection
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK, WebSocketException

from common import create_body
from config import config
from crypto import (
    generate_rsa_keypair, load_private_key, load_public_key,
    rsa_encrypt, rsa_decrypt, compute_content_sig, verify_content_sig, compute_public_content_sig
)
from models import MsgType, current_timestamp, generate_uuid, ProtocolMessage, UserDeliverPayload, CommandResponsePayload, UserAdvertisePayload, \
    MsgDirectPayload, MsgPublicChannelPayload, CommandPayload, UserHelloPayload

logging.basicConfig(level=config.logging_level, format=config.logging_format)
logger = logging.getLogger("Client")


class Client:
    def __init__(self, server_host: str, server_port: int, reconnect_attempts: int = 3):
        self.server_uri = f"ws://{server_host}:{server_port}/ws"
        self.user_id: Optional[str] = None
        self.private_key_b64: Optional[str] = None
        self.public_key_b64: Optional[str] = None
        self.websocket: Optional[Union[ClientConnection, ServerConnection]] = None
        self.known_pubkeys: Dict[str, str] = {}  # user_id -> pubkey
        self._listen_task: Optional[asyncio.Task] = None
        self._reconnect_attempts = max(1, reconnect_attempts)

    def init_user(self, user_id: Optional[str] = None):
        self.user_id = user_id or generate_uuid()
        self.private_key_b64, self.public_key_b64 = generate_rsa_keypair()
        logger.info(f"user_id={self.user_id}")

    async def connect(self):
        """Connect once, send USER_HELLO, then start the listener task."""
        attempt = 0
        last_err: Optional[Exception] = None
        while attempt < self._reconnect_attempts:
            attempt += 1
            try:
                logger.info(f"connecting to {self.server_uri} (attempt {attempt}/{self._reconnect_attempts})")
                # Small open timeout to fail fast if server isn’t listening.
                self.websocket = await asyncio.wait_for(connect(self.server_uri, logger=logger), timeout=6)
                await self._send_user_hello()
                logger.info("connected and sent USER_HELLO")
                # Start background listener
                self._listen_task = asyncio.create_task(self.listen(), name="client-listen")
                return
            except (asyncio.TimeoutError, ConnectionClosedError, ConnectionClosedOK, WebSocketException, OSError) as e:
                last_err = e
                logger.warning(f"connect failed: {e!r}")
                await asyncio.sleep(1.0)

        # Exhausted retries
        raise RuntimeError(f"Unable to connect to {self.server_uri}") from last_err

    async def _send_user_hello(self):
        assert self.websocket is not None, "websocket not connected"
        hello_pl = UserHelloPayload(client="local-cli-v1", pubkey=self.public_key_b64).model_dump()
        body = create_body(MsgType.USER_HELLO, self.user_id, "server", hello_pl)
        await self.websocket.send(body)

    async def listen(self):
        """Background listener; exits when the socket closes."""
        assert self.websocket is not None
        ws = self.websocket
        try:
            async for message in ws:
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    logger.error("Invalid JSON from server")
                    continue
                msg = ProtocolMessage(**data)
                await self.handle_message(msg)
        except (ConnectionClosedOK, ConnectionClosedError) as e:
            logger.info(f"Connection closed: {e!r}")
        except Exception as e:
            logger.error(f"Listen loop crashed: {e!r}")

    async def handle_message(self, msg: ProtocolMessage):
        mtype = msg.type

        match mtype:
            case MsgType.USER_DELIVER:
                await self._on_user_deliver(msg)
            case MsgType.COMMAND_RESPONSE:
                await self._handle_command_response(msg)
            case MsgType.USER_ADVERTISE:
                await self._handle_user_advertise(msg)
            case MsgType.ERROR:
                logger.error("ERROR: %s", msg.payload)
            case _:
                logger.error(f"Unknown message type: {mtype} for request: {msg}")

    async def _on_user_deliver(self, data: ProtocolMessage):
        payload = UserDeliverPayload(**data.payload)
        try:
            ciphertext = payload.ciphertext
            sender_id = payload.sender  # set by server on fanout
            sender_pub = payload.sender_pub
            sender_pub_key = load_public_key(sender_pub)

            # Try to verify against the *sender id*, not the server id.
            # NOTE: The original timestamp used by the sender to sign may not be present,
            # so verification can fail in some deployments; keep it best-effort.
            try:
                ok = verify_content_sig(
                    sender_pub_key,
                    ciphertext,
                    sender_id,
                    data.to,
                    data.ts,
                    payload.content_sig,
                )
                if not ok:
                    logger.debug("content_sig failed verification (best-effort)")
            except Exception:
                logger.debug("content_sig verify raised; continuing", exc_info=True)

            plaintext = rsa_decrypt(load_private_key(self.private_key_b64), ciphertext)
            msg_txt = plaintext.decode("utf-8", errors="replace")
            print(f"[DM] {sender_id}: {msg_txt}")
        except Exception as e:
            logger.exception(f"failed to decrypt/verify: {e!r}")

    async def _handle_command_response(self, data: ProtocolMessage):
        payload = CommandResponsePayload(**data.payload)
        command = payload.command
        response = json.loads(payload.response)
        match command:
            case "/list":
                users = response.get("users", [])
                logger.info("Online users: %s", ", ".join(users))
            case _:
                logger.error(f"Unknown command response: {command}")

    async def _handle_user_advertise(self, data: ProtocolMessage):
        payload = UserAdvertisePayload(**data.payload)
        uid = payload.user_id
        pub = payload.pubkey
        if uid and pub:
            self.known_pubkeys[uid] = pub
            logger.info("user online: %s", uid)

    async def send_command(self, line: str):
        if not self.websocket:
            logger.error("not connected")
            return

        parts = line.split()
        if not parts:
            return
        cmd = parts[0]

        if cmd == "/tell" and len(parts) >= 3:
            target = parts[1]
            msg_text = " ".join(parts[2:])
            if target not in self.known_pubkeys:
                logger.error("Unknown user: %s", target)
                return
            target_pk = load_public_key(self.known_pubkeys[target])
            ciphertext = rsa_encrypt(target_pk, msg_text.encode("utf-8"))
            ts = current_timestamp()
            content_sig = compute_content_sig(load_private_key(self.private_key_b64), ciphertext, self.user_id, target, ts)
            dm_pl = MsgDirectPayload(ciphertext=ciphertext, sender_pub=self.public_key_b64, content_sig=content_sig).model_dump()
            body = create_body(MsgType.MSG_DIRECT, self.user_id, target, dm_pl)
            await self.websocket.send(body)
            return

        if cmd == "/all" and len(parts) >= 2:
            msg_text = " ".join(parts[1:])
            # TODO: fix: public is signed but not encrypted (spec may allow RSA group key)
            ciphertext = msg_text
            ts = current_timestamp()
            content_sig = compute_public_content_sig(load_private_key(self.private_key_b64), ciphertext, self.user_id, ts)
            pub_pl = MsgPublicChannelPayload(ciphertext=ciphertext, sender_pub=self.public_key_b64, content_sig=content_sig).model_dump()
            body = create_body(MsgType.MSG_PUBLIC_CHANNEL, self.user_id, "public", pub_pl)
            await self.websocket.send(body)
            return

        if cmd == "/list":
            comm_pl = CommandPayload(command="/list").model_dump()
            body = create_body(MsgType.COMMAND, self.user_id, "server", comm_pl)
            await self.websocket.send(body)
            return

        logger.error("Unknown command: %s", cmd)

    async def close(self):
        """Close the socket and cancel listener."""
        try:
            if self._listen_task and not self._listen_task.done():
                self._listen_task.cancel()
                try:
                    await self._listen_task
                except asyncio.CancelledError:
                    pass
        finally:
            if self.websocket:
                try:
                    await self.websocket.close()
                except Exception:
                    logger.debug("close() failed", exc_info=True)
            self.websocket = None


async def interactive_client():
    # Resolve host/port/user from CLI or env; defaults align with server defaults.
    host = os.getenv("SERVER_HOST", "127.0.0.1")
    port = int(os.getenv("SERVER_PORT", "8080"))
    uid = None

    # CLI: python client.py [user_id] [host] [port]
    if len(sys.argv) >= 2 and sys.argv[1]:
        uid = sys.argv[1]
    if len(sys.argv) >= 3 and sys.argv[2]:
        host = sys.argv[2]
    if len(sys.argv) >= 4 and sys.argv[3]:
        try:
            port = int(sys.argv[3])
        except ValueError:
            logger.error("Invalid port: %s", sys.argv[3])

    client = Client(server_host=host, server_port=port, reconnect_attempts=3)
    client.init_user(uid)

    try:
        await client.connect()
    except Exception as e:
        logger.error("giving up connecting to %s:%s: %r", host, port, e)
        return

    print("Commands:")
    print("- /list")
    print("- /tell <user> <msg>")
    print("- /all <msg>")
    print("- /quit")

    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                line = await loop.run_in_executor(None, input, "")
            except EOFError:
                break
            line = (line or "").strip()
            if not line:
                continue
            if line == "/quit":
                break
            await client.send_command(line)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Interactive loop error: {e!r}")
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(interactive_client())
    except KeyboardInterrupt:
        print()
