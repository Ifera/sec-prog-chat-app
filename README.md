# Secure Chat (Introducer + Peer Servers + RSA Clients)

A multi-server chat system over WebSockets. It consists of:

- Introducer: a simple directory server that assigns IDs to servers and shares a roster of known servers/clients at join time.
- Peer chat servers: connect to an introducer and to each other, relay messages, gossip user presence, and deliver messages to local clients.
- Clients: connect to a server, generate an ephemeral RSA keypair, and exchange messages. Direct messages are end-to-end encrypted with RSA; public channel messages are signed but not encrypted.

The code uses:
- websockets (asyncio) for networking
- cryptography (RSA-4096 OAEP/PSS) for encryption and signatures
- pydantic for message schemas and validation
- sqlite (chat.db) to store user roster and a placeholder public channel/group schema

---

## Features

- Introducer-based discovery: servers join an introducer to get an ID and learn about other servers and online clients
- Server-to-server links: servers announce themselves and relay public and direct messages
- User presence gossip: servers broadcast USER_ADVERTISE/USER_REMOVE to keep rosters fresh
- End-to-end RSA direct messages: clients encrypt to the recipient's public key and attach a content signature
- Signed public messages: public channel messages are signed by the sender (not encrypted; see Security notes)
- Health monitoring/heartbeats between servers
- Simple CLI client with commands: /list, /tell <user> <msg>, /all <msg>, /quit

## Quick start (Windows, cmd.exe)

Prerequisites:
- Python 3.12+ (tested with 3.12)
- Windows command prompt (cmd.exe)

Create a virtual environment and install dependencies:

```cmd
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 1) Start an Introducer

You can use the helper script (reads .introducer.env if present):

```cmd
start_introducer.bat
```

Or start with explicit args (defaults: HOST=127.0.0.1, PORT=8000):

```cmd
start_introducer.bat 8000 introducers.json
```

Or run directly with environment variables:

```cmd
set HOST=127.0.0.1
set PORT=8000
set INTRODUCERS_JSON=introducers.json
python introducer.py
```

### 2) Start one or more Servers

Use the helper script (reads .server.env if present):

```cmd
start_server.bat
```

With explicit args: <PORT> <HOST> <INTRODUCERS_JSON>

```cmd
start_server.bat 8080 127.0.0.1 introducers.json
```

Or run directly with environment variables (server defaults in code are HOST=0.0.0.0, PORT=8082 if you don’t override):

```cmd
set HOST=127.0.0.1
set PORT=8080
set INTRODUCERS_JSON=introducers.json
python server.py
```

Start multiple servers by using different PORT values; they will all try to connect to the introducer(s) listed in introducers.json and then to each other.

### 3) Start a Client

Connect a client to a server (user_id optional; if omitted, a random UUID is generated):

```cmd
start_client.bat
```

With explicit args: <USER_ID> <SERVER_HOST> <SERVER_PORT>

```cmd
start_client.bat alice 127.0.0.1 8080
```

Or run directly:

```cmd
python client.py alice 127.0.0.1 8080
```

Client commands:
- /list — list currently known online users
- /tell <user> <msg> — send an RSA-encrypted direct message
- /all <msg> — post a signed message to the public channel (not encrypted)
- /quit — exit

---

## Quick start (Linux/macOS)

Prerequisites:
- Python 3.12+ (tested with 3.12)
- Bash-compatible shell

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Mark helper scripts executable (first time only):

```bash
chmod +x start_introducer.sh start_server.sh start_client.sh
```

### 1) Start an Introducer

Use the helper script (reads `.introducer.env` if present):

```bash
./start_introducer.sh
```

Or with explicit args (defaults: HOST=127.0.0.1, PORT=8000):

```bash
./start_introducer.sh 8000 introducers.json
```

Or run directly with environment variables:

```bash
HOST=127.0.0.1 PORT=8000 INTRODUCERS_JSON=introducers.json python3 introducer.py
```

### 2) Start one or more Servers

Use the helper script (reads `.server.env` if present):

```bash
./start_server.sh
```

With explicit args: <PORT> <HOST> <INTRODUCERS_JSON>

```bash
./start_server.sh 8080 127.0.0.1 introducers.json
```

Or run directly with environment variables (server defaults in code are HOST=0.0.0.0, PORT=8082 if you don’t override):

```bash
HOST=127.0.0.1 PORT=8080 INTRODUCERS_JSON=introducers.json python3 server.py
```

Start multiple servers by using different PORT values; they will all try to connect to the introducer(s) listed in `introducers.json` and then to each other.

### 3) Start a Client

Connect a client to a server (user_id optional; if omitted, a random UUID is generated):

```bash
./start_client.sh
```

With explicit args: <USER_ID> <SERVER_HOST> <SERVER_PORT>

```bash
./start_client.sh alice 127.0.0.1 8080
```

Or run directly:

```bash
python3 client.py alice 127.0.0.1 8080
```

Client commands are the same as Windows.

---

## How it works (Architecture)

- Introducer (introducer.py)
  - Accepts SERVER_HELLO_JOIN and replies with SERVER_WELCOME containing:
    - assigned_id for the joining server
    - the list of known servers (host, port, pubkey)
    - the list of known clients (user_id, server_id, pubkey) at that moment
  - Tracks USER_ADVERTISE and USER_REMOVE to maintain a directory of users; does not relay chat messages
  - Sends/receives heartbeats from servers (accepts HEARTBEAT silently)

- Chat Server (server.py)
  - On start, bootstraps by connecting to introducers (from introducers.json or environment), sending SERVER_HELLO_JOIN
  - Receives SERVER_WELCOME, sets its server_id, then connects to peer servers and sends SERVER_ANNOUNCE
  - Accepts client connections and USER_HELLO, stores user pubkeys in chat.db
  - Gossips USER_ADVERTISE/USER_REMOVE to peers and the introducer
  - Delivers messages:
    - Direct: local delivery if the recipient is connected; otherwise forwards to the recipient’s server
    - Public: broadcasts to all local clients and forwards to peer servers (fan-out)

- Client (client.py)
  - Generates an ephemeral RSA-4096 keypair on startup
  - Sends USER_HELLO to the server; learns other users’ pubkeys via USER_ADVERTISE messages
  - /tell uses RSA OAEP to encrypt to the recipient public key and signs the content; /all signs plaintext for the public channel

- Base Infrastructure (base_server.py)
  - Common WebSocket server lifecycle, graceful shutdown, and a heartbeat/health monitor between servers

---

## Configuration

Configuration is primarily via environment variables; defaults are applied in code (config.py). Batch scripts (.bat) load optional .server.env and .introducer.env files.

Key environment variables:
- HOST: Bind address for the process (default introducer script: 127.0.0.1; code default: 0.0.0.0)
- PORT: Listening port (default introducer script: 8000; server script default: 8080; code default: 8082)
- INTRODUCERS_JSON: Path to an introducer list JSON (default: introducers.json)
- DB_PATH: SQLite database file path (default: chat.db)
- HEARTBEAT_INTERVAL: Seconds between probes (default: 15)
- TIMEOUT_THRESHOLD: Seconds to consider a peer dead (default: 45)

Introducers list file (introducers.json):

```json
{
  "bootstrap_servers": [
    { "host": "127.0.0.1", "port": 8000, "pubkey": "" },
    { "host": "127.0.0.1", "port": 8001, "pubkey": "" },
    { "host": "127.0.0.1", "port": 8002, "pubkey": "" }
  ]
}
```

Fallback bootstrap envs if INTRODUCERS_JSON can’t be read:
- BOOTSTRAP_HOST_1, BOOTSTRAP_PORT_1, BOOTSTRAP_PUBKEY_1
- BOOTSTRAP_HOST_2, BOOTSTRAP_PORT_2, BOOTSTRAP_PUBKEY_2
- BOOTSTRAP_HOST_3, BOOTSTRAP_PORT_3, BOOTSTRAP_PUBKEY_3

WebSocket endpoint: all servers listen on ws://HOST:PORT/ws

---

## Data model (SQLite chat.db)

Created automatically on server start (database.py):
- users(user_id TEXT PRIMARY KEY, pubkey TEXT, privkey_store TEXT, pake_password TEXT, meta JSON, version INT)
- groups(group_id TEXT PRIMARY KEY, creator_id TEXT, created_at INT, meta JSON, version INT)
- group_members(group_id, member_id, role, wrapped_key, added_at)

A default public group row is created on first run.

Currently, the running system uses users for storing pubkeys and presence.

---

## Protocol (high level)

Message envelope fields (models.ProtocolMessage):
- type: MsgType
- from: sender id (server_id or user_id)
- to: recipient (server_id, user_id, or "public")
- ts: timestamp (ms)
- payload: typed JSON object depending on message type
- sig: optional transport signature (server-signed canonical payload)

Main message types (not exhaustive):
- Server to Server / Introducer: SERVER_HELLO_JOIN, SERVER_WELCOME, SERVER_ANNOUNCE, SERVER_GOODBYE, HEARTBEAT, USER_ADVERTISE, USER_REMOVE, SERVER_DELIVER
- Client to Server: USER_HELLO, MSG_DIRECT, MSG_PUBLIC_CHANNEL, USER_DELIVER, COMMAND (/list), COMMAND_RESPONSE

Content security:
- Direct messages (MSG_DIRECT) are RSA-encrypted with the recipient’s public key and include a sender content signature
- Public messages (MSG_PUBLIC_CHANNEL) are plaintext but signed by the sender
- Servers may compute a transport signature over the canonical payload for hop integrity

---

## Security notes (Important)

- Client keypairs are ephemeral per process run and not persisted by default
- Servers also generate ephemeral RSA keypairs on startup
- Public channel messages are not encrypted; they are signed (integrity, authenticity) but readable by anyone
- No user authentication, authorization, or long-term identity management is implemented
- No TLS; transport is plain ws://
- Signature verification on the client is best-effort and may skip under certain conditions (see client.py comments)

---

## Troubleshooting

- Port in use: change PORT for servers/introducers or stop the conflicting process
- Can’t connect to introducer: servers will retry and eventually operate “standalone” (no peer routing) if all introducers are unreachable
- Client can’t /tell a user: ensure you’ve received a USER_ADVERTISE for that user (they must be online somewhere in the network)
- Resetting state: stop servers and delete chat.db to reset the local roster; then restart
- Logs: logging is to stdout; adjust logging level/format in config.py if needed

---

## Development notes

- Python formatting: not enforced here; keep style consistent with the repo
- Dependencies: see requirements.txt
- Run targets: introducer.py, server.py, client.py; helper scripts: start_introducer.bat, start_server.bat, start_client.bat

---
