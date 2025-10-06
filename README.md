# Secure Chat (Introducer + Peer Servers + RSA Clients)

A multi-server chat system over WebSockets. It consists of:

## Overview

- **Topology**: n-to-n mesh of peer servers.
- **Transport**: WebSocket (RFC 6455), one JSON object per message.
- **Cryptography**: RSA-4096 with OAEP encryption and PSS signatures.
- **Features**: End-to-end encrypted direct messages, signed public channel messages, user presence gossip, server bootstrap via introducers, file transfers, heartbeat health checks.
- **Frontend**: Command-line client (Python) and web interface (React).

## Features

- **Server Bootstrap and Discovery**: Servers join the network via introducers, receiving server IDs and client lists.
- **Presence Gossip**: User online status is gossiped across servers (USER_ADVERTISE/USER_REMOVE).
- **Forwarded Delivery**: Messages are routed hop-by-hop to recipient servers.
- **Direct Messages (E2EE)**: RSA-encrypted payloads between users.
- **Public Channel Messaging**: Signed and encrypted broadcast messages.
- **File Transfer**: Secure file sharing via DMs or public channels.
- **Health Monitoring**: Server-to-server heartbeats with configurable timeouts.
- **Mandatory Commands**: /list (online users), /tell (DM), /all (public), /file (transfer).
- **Frontend**: Command-line client (Python) and web interface (React).

# Backend

## Quick Start (Windows, cmd.exe)

Prerequisites:
- Python 3.12+
- Tested with Python 3.12
- Windows Command Prompt (cmd.exe)
- **Execute commands in `backend/` directory**

Create a virtual environment and install dependencies:

```cmd
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 1) Start an Introducer

Use the helper script (reads .introducer.env if present):

```cmd
start_introducer.bat
```

With explicit args (defaults: HOST=127.0.0.1, PORT=8000):

```cmd
start_introducer.bat 8000 introducers.json
```

Or run directly (defaults apply if not overridden in config.py):

```cmd
set HOST=127.0.0.1
set PORT=8000
set INTRODUCERS_JSON=introducers.json
python introducer.py
```

### 2) Start Peer Servers

Use the helper script (reads .server.env if present):

```cmd
start_server.bat
```

With args: <PORT> <HOST> <INTRODUCERS_JSON> (server defaults: HOST=0.0.0.0, PORT=8082)

```cmd
start_server.bat 8080 127.0.0.1 introducers.json
```

Run directly:

```cmd
set HOST=127.0.0.1
set PORT=8080
set INTRODUCERS_JSON=introducers.json
python server.py
```

Start multiple to form a mesh; they bootstrap and announce via introducers.

### 3) Start Clients

Connect with a user ID (random UUID if omitted):

```cmd
start_client.bat
```

With args: <USER_ID[str|uuid]> <SERVER_HOST> <SERVER_PORT>

```cmd
start_client.bat alice 127.0.0.1 8080
```

Run directly:

```cmd
python client.py alice 127.0.0.1 8080
```

Commands:
- /list — List known online users
- /tell <user> <msg> — Send RSA-encrypted DM
- /all <msg> — Post signed public channel message
- /file <user> <path> — Initiate secure file transfer (DM only, per SOCP)
- /quit — Disconnect

## Quick Start (Linux/macOS)

Prerequisites: Python 3.12+, Bash-compatible shell

Setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
chmod +x start_*.sh
```

Run commands same as Windows but with .sh scripts and python3.

# Frontend

## Requirements

- Node.js: v18+ (recommended LTS)
- npm
- Modern browser with WebCrypto support
- Backend server running locally

## Install and Run

- npm install
- npm start
- Open http://localhost:3000

## HOW TO USE (DEMO STEPS)

- Start the backend server (see backend section above).
- Open two browser windows/tabs to http://localhost:3000.
- Wait until footer shows: "SOCP WS: connected".
- Select a user on the left to start a direct chat.
- For Public channel: click "#public", type message, press Enter.
- File transfer: click the paper-clip (Attach) → choose file → it sends as DM or to public depending on current conversation.
- Download a received file: click "Download" link in the message bubble.

# Architecture (SOCP Protocol Implementation)

### Introducer (introducer.py)
- Manages server joins (SERVER_HELLO_JOIN → SERVER_WELCOME with assigned ID and peer list).
- Maintains user directory via USER_ADVERTISE/USER_REMOVE; does not relay chat.

### Peer Chat Server (server.py)
- Bootstraps via introducers (uses introducers.json or envs), sends SERVER_HELLO_JOIN, receives SERVER_WELCOME.
- Announces new servers (SERVER_ANNOUNCE) and connects to peers.
- Handles USER_HELLO, stores pubkeys (RSA-4096) in chat.db.
- Gossips presence and routes/forward messages:
  - Direct: E2EE to local/forward via SERVER_DELIVER.
  - Public: Fan-out to all servers/cliehts.
- Relays USER_ADVERTISE/USER_REMOVE across network.

### Client (client.py)
- Generates ephemeral RSA-4096 keypair per run.
- Sends USER_HELLO on connect.
- Encrypts DMs with recipient's pubkey (OAEP), signs content (PSS).
- Verifies incoming messages.

### Base Server (base_server.py)
- Common asyncio WebSocket server with graceful shutdown and health monitoring.

## Protocol Details

- **JSON Envelope**: All messages include type, from, to, ts, payload, sig (transport signature over payload).
- **Server ↔ Server**: Bootstrap, gossip (USER_ADVERTISE/USER_REMOVE), forwarded delivery (SERVER_DELIVER), heartbeats.
- **User ↔ Server**: USER_HELLO, MSG_DIRECT (E2EE), MSG_PUBLIC_CHANNEL (signed), file transfer (FILE_START/CHUNK/END).
- **Routing**: Use user_locations table; forward to recipient server if not local.
- **Signing & Verification**: Transport sig on all server messages; content_sig on E2EE payloads.
- **Errors**: Standard codes: USER_NOT_FOUND, INVALID_SIG, BAD_KEY, TIMEOUT, UNKNOWN_TYPE, NAME_IN_USE.

## Configuration

Via environment variables or .env files (introder .introducer.env, server .server.env).

Key vars:
- HOST: Bind address (default server: 0.0.0.0)
- PORT: Listen port (default introducer: 8000, server scripts: 8080, code: 8082)
- INTRODUCERS_JSON: Path to JSON list
- DB_PATH: SQLite file (default: chat.db)
- HEARTBEAT_INTERVAL: Seconds (default: 15)
- TIMEOUT_THRESHOLD: Seconds (default: 45)

Introducer list (introducers.json):

```json
{
  "bootstrap_servers": [
    {"host": "127.0.0.1", "port": 8000, "pubkey": ""},
    {"host": "127.0.0.1", "port": 8001, "pubkey": ""},
    {"host": "127.0.0.1", "port": 8002, "pubkey": ""}
  ]
}
```

Fallback envs: BOOTSTRAP_HOST_1, etc.

WebSocket endpoint: ws://HOST:PORT/ws

## Server Database Schema

SQLite (chat.db), created on server start:

- **users**: user_id (TEXT PK), pubkey (TEXT), privkey_store (TEXT), pake_password (TEXT), meta (JSON), version (INT)
- **groups**: group_id (TEXT PK), creator_id (TEXT), created_at (INT), meta (JSON), version (INT)
  - Public channel: group_id="public", creator_id="system"
- **group_members**: group_id (TEXT), member_id (TEXT), role (TEXT), wrapped_key (TEXT), added_at (INT)
  - Public: all members role="member", keys wrapped with RSA-OAEP

Default public group entry created on startup.

## Mandatory Features (SOCP Compliance)

All REQUIRED for interoperability:
- /list: Sort/return known online users.
- /tell <user> <text>: DM via RSA E2EE.
- /all <text>: Public channel broadcast (signed).
- /file <user> <path>: File transfer via encrypted chunks.
- Bootstrap via introducers.
- Presence gossip.
- Message forwarding/routing without decryption.
- RSA-4096 OAEP/PSS, SHA-256 hashing.
- Transport sigs on server msg, content sigs on E2EE.
- Heartbeats (15s) and 45s timeouts.

## Security Notes

- RSA-4096 only (no AES as of v1.3).
- E2EE DMs: Encrypted to recipient pubkey, signed by sender.
- Public messages: Signed and encrypted.
- Server keys ephemeral per run (no persistence).
- No user auth/authority; client keys ephemeral.
- Direct WebSocket (no TLS).
- Client verification best-effort; enforces content sigs.

## Troubleshooting

- Port conflicts: Change PORTs, stop competing processes.
- No introducer: Retry bootstrap, operate standalone if all unreachable.
- DM fails: Await USER_ADVERTISE for user.
- Reset database: Delete chat.db, restart.
- Logs: Console output; adjust in config.py.
- Connection issues: Check firewall, ports, correct WebSocket URLs.

## Backdoors (Assignment Requirement)

This implementation includes intentional vulnerabilities as per SOCP v1.3 Section 16 (assignment requirement). At least 2 non-exhaustive backdoors are present:

## Compliance Checklist

- [x] RSA-4096 keys; OAEP encryption, PSS signatures
- [x] WebSocket transport, JSON envelopes
- [x] User content with content_sig
- [x] Server msgs with transport sig
- [x] Bootstrap via introducers
- [x] USER_ADVERTISE/USER_REMOVE gossip
- [x] SERVER_DELIVER routing with loop suppression
- [x] Heartbeats/45s timeout
- [x] Error codes implemented
- [x] Mandatory commands (/list, /tell, /all, /file)
- [x] Database schema includes users/groups/group_members

## Development Notes

- Formatting: Follow project style.
- Dependencies: requirements.txt
- Targets: introducer.py, server.py (single per PORT?), client.py
- Scripts: start_*.bat for Windows, .sh for Unix

