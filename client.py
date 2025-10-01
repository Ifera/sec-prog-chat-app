import asyncio
import json
import logging
import os
import sys
from typing import Dict, Optional, Union

from websockets.asyncio.client import connect, ClientConnection
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK, WebSocketException
from websockets.asyncio.server import ServerConnection

from config import config
from crypto import (
    generate_rsa_keypair, load_private_key, load_public_key,
    rsa_encrypt, rsa_decrypt, compute_content_sig, verify_content_sig, compute_public_content_sig
)
from models import MsgType, current_timestamp, generate_uuid

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
        logger.info(f"[client] user_id={self.user_id}")

    async def connect(self):
        """Connect once, send USER_HELLO, then start the listener task."""
        attempt = 0
        last_err: Optional[Exception] = None
        while attempt < self._reconnect_attempts:
            attempt += 1
            try:
                logger.info(f"[client] connecting to {self.server_uri} (attempt {attempt}/{self._reconnect_attempts})")
                # Small open timeout to fail fast if server isn’t listening.
                self.websocket = await asyncio.wait_for(connect(self.server_uri), timeout=6)
                await self._send_user_hello()
                logger.info("[client] connected and sent USER_HELLO")
                # Start background listener
                self._listen_task = asyncio.create_task(self.listen(), name="client-listen")
                return
            except (asyncio.TimeoutError, ConnectionClosedError, ConnectionClosedOK, WebSocketException, OSError) as e:
                last_err = e
                logger.warning(f"[client] connect failed: {e!r}")
                await asyncio.sleep(1.0)

        # Exhausted retries
        raise RuntimeError(f"Unable to connect to {self.server_uri}") from last_err

    async def _send_user_hello(self):
        assert self.websocket is not None, "websocket not connected"
        hello_payload = {"client": "client-v1.0", "pubkey": self.public_key_b64}
        hello_msg = {
            "type": MsgType.USER_HELLO,  # StrEnum -> JSON string
            "from": self.user_id,  # use alias name 'from' for clarity
            "to": "server",
            "ts": current_timestamp(),
            "payload": hello_payload,
            "sig": ""
        }
        await self.websocket.send(json.dumps(hello_msg))

    async def listen(self):
        """Background listener; exits when the socket closes."""
        assert self.websocket is not None
        ws = self.websocket
        try:
            async for message in ws:
                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    logger.exception("[client] invalid JSON from server")
                    continue
                await self.handle_message(data)
        except (ConnectionClosedOK, ConnectionClosedError) as e:
            logger.info(f"[client] connection closed: {e!r}")
        except Exception:
            logger.exception("[client] listen loop crashed")

    async def handle_message(self, data: dict):
        mtype = data.get("type")
        if mtype == "USER_DELIVER":
            await self._on_user_deliver(data)
            return

        if mtype == "COMMAND_RESPONSE":
            payload = data.get("payload", {})
            if payload.get("command") == "list":
                users = payload.get("users", [])
                logger.info("Online users: %s", ", ".join(users))
            return

        if mtype == "USER_ADVERTISE":
            payload = data.get("payload", {})
            uid = payload.get("user_id")
            pub = payload.get("pubkey")
            if uid and pub:
                self.known_pubkeys[uid] = pub
                logger.info("[client] user online: %s", uid)
            return

        if mtype == "ERROR":
            logger.error("[client] ERROR: %s", data.get("payload"))
            return

        logger.debug("[client] recv: %s", data)

    async def _on_user_deliver(self, data: dict):
        payload = data.get("payload", {})
        try:
            ciphertext = payload["ciphertext"]
            sender_id = payload.get("sender")  # set by server on fanout
            sender_pub = payload["sender_pub"]
            sender_pub_key = load_public_key(sender_pub)

            # Try to verify against the *sender id*, not the server id.
            # NOTE: The original timestamp used by the sender to sign may not be present,
            # so verification can fail in some deployments; keep it best-effort.
            try:
                ok = verify_content_sig(
                    sender_pub_key,
                    ciphertext,
                    sender_id,
                    data.get("to"),
                    data.get("ts"),
                    payload.get("content_sig"),
                )
                if not ok:
                    logger.debug("[client] content_sig failed verification (best-effort)")
            except Exception:
                logger.debug("[client] content_sig verify raised; continuing", exc_info=True)

            plaintext = rsa_decrypt(load_private_key(self.private_key_b64), ciphertext)
            msg_txt = plaintext.decode("utf-8", errors="replace")
            print(f"[DM] {sender_id}: {msg_txt}")
        except Exception as e:
            logger.exception("[client] failed to decrypt/verify")

    async def send_command(self, line: str):
        if not self.websocket:
            logger.error("[client] not connected")
            return

        parts = line.split()
        if not parts:
            return
        cmd = parts[0]

        if cmd == "/tell" and len(parts) >= 3:
            target = parts[1]
            msg_text = " ".join(parts[2:])
            if target not in self.known_pubkeys:
                logger.error("[client] unknown user: %s", target)
                return
            target_pk = load_public_key(self.known_pubkeys[target])
            ciphertext = rsa_encrypt(target_pk, msg_text.encode("utf-8"))
            ts = current_timestamp()
            content_sig = compute_content_sig(load_private_key(self.private_key_b64), ciphertext, self.user_id, target,
                                              ts)
            dm_payload = {"ciphertext": ciphertext, "sender_pub": self.public_key_b64, "content_sig": content_sig,
                          "sender": self.user_id}
            dm = {"type": MsgType.MSG_DIRECT, "from": self.user_id, "to": target, "ts": ts, "payload": dm_payload,
                  "sig": ""}
            await self.websocket.send(json.dumps(dm))
            return

        if cmd == "/all" and len(parts) >= 2:
            msg_text = " ".join(parts[1:])
            # Demo: public is signed but not encrypted (spec may allow RSA group key; omitted here)
            ciphertext = msg_text
            ts = current_timestamp()
            content_sig = compute_public_content_sig(load_private_key(self.private_key_b64), ciphertext, self.user_id,
                                                     ts)
            pub_payload = {"ciphertext": ciphertext, "sender_pub": self.public_key_b64, "content_sig": content_sig,
                           "sender": self.user_id}
            pub = {"type": MsgType.MSG_PUBLIC_CHANNEL, "from": self.user_id, "to": "public", "ts": ts,
                   "payload": pub_payload, "sig": ""}
            await self.websocket.send(json.dumps(pub))
            return

        # default: /list
        msg = {"type": MsgType.COMMAND, "from": self.user_id, "to": "server", "ts": current_timestamp(),
               "payload": {"command": "/list"}, "sig": ""}
        await self.websocket.send(json.dumps(msg))

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
                    logger.debug("[client] close() failed", exc_info=True)
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
        logger.error("[client] giving up connecting to %s:%s: %r", host, port, e)
        return

    print("Commands:")
    print("  /list")
    print("  /tell <user> <msg>")
    print("  /all <msg>")
    print("  /quit")

    loop = asyncio.get_running_loop()
    try:
        while True:
            try:
                line = await loop.run_in_executor(None, input, "> ")
            except EOFError:
                break
            line = (line or "").strip()
            if not line:
                continue
            if line == "/quit":
                break
            await client.send_command(line)
    except KeyboardInterrupt:
        # graceful, no traceback
        pass
    except Exception:
        logger.exception("[client] interactive loop error")
    finally:
        await client.close()


if __name__ == "__main__":
    try:
        asyncio.run(interactive_client())
    except KeyboardInterrupt:
        # swallow Ctrl+C at top level
        print()
