import asyncio
import json
import logging
import websockets
from websockets.exceptions import ConnectionClosedError

from database import Database
from crypto import *
from models import *
from config import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory tables as per spec
servers: dict[int, websockets.WebSocketServerProtocol] = {}  # server_id -> WebSocket connection
server_addrs: dict[int, tuple] = {}  # server_id -> (host, port)
local_users: dict[str, websockets.WebSocketServerProtocol] = {}  # user_id -> WebSocket connection
user_locations: dict[str, str] = {}  # user_id -> "local" | f"server_{id}"

# Server state
server_id = None
server_private_key = None
server_public_key = None
db = Database(config.db_path)

# Introducer state (if acting as introducer)
known_servers: dict[str, dict] = {}  # server_id -> {"host": "", "port": "", "pubkey": ""}

# Seen message cache for loop prevention
seen_messages: set[str] = set()

def init_server():
    global server_id, server_private_key, server_public_key
    server_id = generate_uuid()
    server_private_key, server_public_key = generate_rsa_keypair()
    logger.info(f"Server initialized with ID: {server_id}")

async def bootstrap_to_network():
    """Bootstrap this server into the network by connecting to introducers"""
    global server_id
    logger.info("Starting network bootstrap...")

    # Retry logic for bootstrap
    max_retries = 5
    retry_delay = 2

    for attempt in range(max_retries):
        for introducer in config.bootstrap_servers:
            if not introducer["host"] or not introducer["port"]:
                continue

            try:
                uri = f"ws://{introducer['host']}:{introducer['port']}/ws"
                logger.info(f"Attempting to connect to introducer: {uri} (attempt {attempt + 1}/{max_retries})")

                websocket = await websockets.connect(uri)

                # Send SERVER_HELLO_JOIN
                join_payload = {
                    "host": config.host,
                    "port": config.port,
                    "pubkey": server_public_key
                }
                join_msg = {
                    "type": "SERVER_HELLO_JOIN",
                    "from": server_id,
                    "to": f"{introducer['host']}:{introducer['port']}",
                    "ts": current_timestamp(),
                    "payload": join_payload,
                    "sig": compute_transport_sig(load_private_key(server_private_key), join_payload)
                }

                await websocket.send(json.dumps(join_msg))
                logger.info("Sent SERVER_HELLO_JOIN to introducer")

                # Wait for SERVER_WELCOME with timeout
                try:
                    response = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                    data = json.loads(response)

                    if data.get("type") == "SERVER_WELCOME":
                        welcome_payload = ServerWelcomePayload(**data["payload"])
                        server_id = welcome_payload.assigned_id
                        logger.info(f"Received SERVER_WELCOME, assigned ID: {server_id}")

                        # Connect to all returned servers
                        for client in welcome_payload.clients:
                            await connect_to_server(client["host"], client["port"], client.get("pubkey"))

                        # Send SERVER_ANNOUNCE to all connected servers
                        await announce_to_network()
                        logger.info("Bootstrap completed successfully")

                        # Keep the introducer connection for listening
                        asyncio.create_task(listen_to_server(websocket, hash(server_id) % 1000000))
                        return
                    else:
                        logger.warning(f"Unexpected response type: {data.get('type')}")

                except asyncio.TimeoutError:
                    logger.warning("Timeout waiting for SERVER_WELCOME")
                    await websocket.close()
                    continue

            except Exception as e:
                logger.warning(f"Failed to bootstrap with introducer {introducer['host']}:{introducer['port']}: {e}")

        if attempt < max_retries - 1:
            logger.info(f"Retrying bootstrap in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)
            retry_delay *= 2  # Exponential backoff

    logger.warning("Bootstrap failed after all retries - continuing without network connection")

async def connect_to_server(host: str, port: int, pubkey: str = None):
    """Connect to another server"""
    try:
        uri = f"ws://{host}:{port}/ws"
        logger.info(f"Connecting to server: {uri}")

        websocket = await websockets.connect(uri)

        # Send SERVER_ANNOUNCE
        announce_payload = {
            "host": config.host,
            "port": config.port,
            "pubkey": server_public_key
        }
        announce_msg = {
            "type": "SERVER_ANNOUNCE",
            "from": server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": announce_payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), announce_payload)
        }

        await websocket.send(json.dumps(announce_msg))

        # Register the connection
        server_id_int = hash(server_id) % 1000000  # Simple hash for demo
        servers[server_id_int] = websocket
        server_addrs[server_id_int] = (host, port)

        logger.info(f"Connected to server at {host}:{port}")

        # Start listening for messages from this server
        asyncio.create_task(listen_to_server(websocket, server_id_int))

    except Exception as e:
        logger.error(f"Failed to connect to server {host}:{port}: {e}")

async def announce_to_network():
    """Send SERVER_ANNOUNCE to all connected servers"""
    announce_payload = {
        "host": config.host,
        "port": config.port,
        "pubkey": server_public_key
    }

    for server_ws in servers.values():
        announce_msg = {
            "type": "SERVER_ANNOUNCE",
            "from": server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": announce_payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), announce_payload)
        }
        try:
            await server_ws.send(json.dumps(announce_msg))
        except:
            pass

async def listen_to_server(websocket: websockets.WebSocketServerProtocol, server_id_int: int):
    """Listen for messages from a connected server"""
    try:
        async for message in websocket:
            data = json.loads(message)
            # Handle server-to-server messages
            if data.get("type") == "USER_ADVERTISE":
                await handle_user_advertise(data)
            elif data.get("type") == "USER_REMOVE":
                await handle_user_remove(data)
            elif data.get("type") == "SERVER_DELIVER":
                await handle_server_deliver(data)
            # Add other server message types as needed
    except Exception as e:
        logger.error(f"Connection to server {server_id_int} lost: {e}")
        # Remove from servers
        if server_id_int in servers:
            del servers[server_id_int]
        if server_id_int in server_addrs:
            del server_addrs[server_id_int]

async def handle_user_advertise(data: dict):
    """Handle USER_ADVERTISE from other servers"""
    payload = UserAdvertisePayload(**data["payload"])
    user_locations[payload.user_id] = f"server_{data['from']}"
    logger.info(f"User {payload.user_id} advertised on server {data['from']}")

async def handle_user_remove(data: dict):
    """Handle USER_REMOVE from other servers"""
    payload = UserRemovePayload(**data["payload"])
    if user_locations.get(payload.user_id) == f"server_{data['from']}":
        del user_locations[payload.user_id]
        logger.info(f"User {payload.user_id} removed from server {data['from']}")

async def handle_server_deliver(data: dict):
    """Handle SERVER_DELIVER from other servers"""
    payload = ServerDeliverPayload(**data["payload"])

    if payload.user_id in local_users:
        # Deliver to local user
        deliver_payload = {
            "ciphertext": payload.ciphertext,
            "sender": payload.sender,
            "sender_pub": payload.sender_pub,
            "content_sig": payload.content_sig
        }
        deliver_msg = {
            "type": "USER_DELIVER",
            "from": server_id,
            "to": payload.user_id,
            "ts": current_timestamp(),
            "payload": deliver_payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), deliver_payload)
        }
        await local_users[payload.user_id].send(json.dumps(deliver_msg))

async def handle_connection(websocket: websockets.WebSocketServerProtocol):
    """Handle incoming WebSocket connections (servers or users)"""
    try:
        # First message should identify the connection type
        message = await websocket.recv()
        data = json.loads(message)

        if data.get("type") == "SERVER_HELLO_JOIN":
            await handle_server_join(websocket, data)
        elif data.get("type") == "SERVER_ANNOUNCE":
            await handle_server_announce(websocket, data)
        else:
            # Assume it's a user connection
            await handle_user_connection(websocket)
    except Exception as e:
        logger.error(f"Error handling connection: {e}")

async def handle_server_join(websocket: websockets.WebSocketServerProtocol, data: dict):
    """Handle SERVER_HELLO_JOIN from new server"""
    payload = ServerHelloJoinPayload(**data["payload"])

    # If acting as introducer
    if config.is_introducer:
        # Check server ID uniqueness
        requested_id = data.get("from")
        if requested_id in known_servers:
            # ID conflict, assign new one
            assigned_id = generate_uuid()
        else:
            assigned_id = requested_id

        # Prepare list of known servers (excluding the new one)
        clients = []
        for sid, sdata in known_servers.items():
            if sid != assigned_id:
                clients.append({
                    "user_id": sid,  # Note: using server_id as user_id for compatibility
                    "host": sdata["host"],
                    "port": sdata["port"],
                    "pubkey": sdata["pubkey"]
                })

        welcome_payload = {
            "assigned_id": assigned_id,
            "clients": clients
        }
    else:
        # Regular server behavior
        assigned_id = data.get("from", generate_uuid())
        welcome_payload = {
            "assigned_id": assigned_id,
            "clients": []
        }

    welcome_msg = {
        "type": "SERVER_WELCOME",
        "from": server_id,
        "to": data["from"],
        "ts": current_timestamp(),
        "payload": welcome_payload,
        "sig": compute_transport_sig(load_private_key(server_private_key), welcome_payload)
    }
    await websocket.send(json.dumps(welcome_msg))

    # Register the server temporarily (will be confirmed by SERVER_ANNOUNCE)
    temp_id = assigned_id
    servers[hash(temp_id) % 1000000] = websocket  # Temporary ID
    server_addrs[hash(temp_id) % 1000000] = (payload.host, payload.port)

async def handle_server_announce(websocket: websockets.WebSocketServerProtocol, data: dict):
    """Handle SERVER_ANNOUNCE"""
    payload = ServerAnnouncePayload(**data["payload"])
    server_id_str = data["from"]
    server_id_int = int(server_id_str)

    # Verify signature if possible
    # TODO: verify sig

    # Register server
    servers[server_id_int] = websocket
    server_addrs[server_id_int] = (payload.host, payload.port)

    # If acting as introducer, add to known servers
    if config.is_introducer:
        known_servers[server_id_str] = {
            "host": payload.host,
            "port": payload.port,
            "pubkey": payload.pubkey
        }
        logger.info(f"Introducer registered server: {server_id_str}")

async def handle_user_connection(websocket: websockets.WebSocketServerProtocol):
    """Handle user WebSocket connection"""
    user_id = None
    try:
        async for message in websocket:
            data = json.loads(message)
            msg = ProtocolMessage(**data)

            if msg.type == "USER_HELLO":
                user_id = await handle_user_hello(websocket, msg)
            elif msg.type == "MSG_DIRECT":
                await handle_msg_direct(msg)
            elif msg.type == "MSG_PUBLIC_CHANNEL":
                await handle_msg_public_channel(msg)
            elif msg.type.startswith("/"):  # Commands
                await handle_command(websocket, msg)
            else:
                logger.warning(f"Unknown message type: {msg.type}")

    except ConnectionClosedError:
        if user_id:
            await handle_user_disconnect(user_id)
    except Exception as e:
        logger.error(f"Error handling user message: {e}")

async def handle_user_hello(websocket: websockets.WebSocketServerProtocol, msg: ProtocolMessage) -> str:
    """Handle USER_HELLO"""
    payload = UserHelloPayload(**msg.payload)

    # Check for duplicate
    if payload.from_ in local_users:
        error_msg = {
            "type": "ERROR",
            "from": server_id,
            "to": payload.from_,
            "ts": current_timestamp(),
            "payload": {"code": "NAME_IN_USE", "detail": "User ID already in use"},
            "sig": compute_transport_sig(load_private_key(server_private_key), {"code": "NAME_IN_USE", "detail": "User ID already in use"})
        }
        await websocket.send(json.dumps(error_msg))
        return None

    # Register user
    local_users[payload.from_] = websocket
    user_locations[payload.from_] = "local"

    # Store in database
    db.add_user(payload.from_, payload.pubkey, "", "", {})  # TODO: proper storage

    # Advertise to network
    await advertise_user(payload.from_)

    return payload.from_

async def advertise_user(user_id: str):
    """Send USER_ADVERTISE to all servers"""
    user_data = db.get_user(user_id)
    if not user_data:
        return

    payload = {
        "user_id": user_id,
        "server_id": server_id,
        "meta": user_data.get("meta", {})
    }

    for server_ws in servers.values():
        msg = {
            "type": "USER_ADVERTISE",
            "from": server_id,
            "to": "*",  # Broadcast
            "ts": current_timestamp(),
            "payload": payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), payload)
        }
        try:
            await server_ws.send(json.dumps(msg))
        except:
            pass  # Handle dead connections

async def handle_user_disconnect(user_id: str):
    """Handle user disconnection"""
    if user_id in local_users:
        del local_users[user_id]
    if user_id in user_locations:
        del user_locations[user_id]

    # Send USER_REMOVE
    payload = {
        "user_id": user_id,
        "server_id": server_id
    }

    for server_ws in servers.values():
        msg = {
            "type": "USER_REMOVE",
            "from": server_id,
            "to": "*",
            "ts": current_timestamp(),
            "payload": payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), payload)
        }
        try:
            await server_ws.send(json.dumps(msg))
        except:
            pass

async def handle_msg_direct(msg: ProtocolMessage):
    """Handle MSG_DIRECT"""
    payload = MsgDirectPayload(**msg.payload)

    if msg.to in local_users:
        # Deliver directly
        deliver_payload = {
            "ciphertext": payload.ciphertext,
            "sender": msg.from_,
            "sender_pub": payload.sender_pub,
            "content_sig": payload.content_sig
        }
        deliver_msg = {
            "type": "USER_DELIVER",
            "from": server_id,
            "to": msg.to,
            "ts": current_timestamp(),
            "payload": deliver_payload,
            "sig": compute_transport_sig(load_private_key(server_private_key), deliver_payload)
        }
        await local_users[msg.to].send(json.dumps(deliver_msg))
    else:
        # Forward via SERVER_DELIVER
        await route_to_user(msg.to, msg)

async def route_to_user(target_user: str, original_msg: ProtocolMessage):
    """Route message to user according to spec"""
    if target_user in local_users:
        # Deliver locally - but this should be handled by caller
        pass
    elif user_locations.get(target_user, "").startswith("server_"):
        server_id_str = user_locations[target_user][7:]  # Remove "server_"
        server_id_int = int(server_id_str)
        if server_id_int in servers:
            deliver_payload = {
                "user_id": target_user,
                "ciphertext": original_msg.payload["ciphertext"],
                "sender": original_msg.from_,
                "sender_pub": original_msg.payload["sender_pub"],
                "content_sig": original_msg.payload["content_sig"]
            }
            deliver_msg = {
                "type": "SERVER_DELIVER",
                "from": server_id,
                "to": server_id_str,
                "ts": current_timestamp(),
                "payload": deliver_payload,
                "sig": compute_transport_sig(load_private_key(server_private_key), deliver_payload)
            }
            try:
                await servers[server_id_int].send(json.dumps(deliver_msg))
            except:
                pass
    else:
        # User not found
        logger.warning(f"User {target_user} not found")

async def handle_msg_public_channel(msg: ProtocolMessage):
    """Handle MSG_PUBLIC_CHANNEL"""
    # For simplicity, broadcast to all local users
    # In full implementation, would handle group keys, etc.

    deliver_payload = {
        "ciphertext": msg.payload["ciphertext"],
        "sender": msg.from_,
        "sender_pub": msg.payload["sender_pub"],
        "content_sig": msg.payload["content_sig"]
    }

    deliver_msg = {
        "type": "USER_DELIVER",
        "from": server_id,
        "to": "*",  # Broadcast to local users
        "ts": current_timestamp(),
        "payload": deliver_payload,
        "sig": compute_transport_sig(load_private_key(server_private_key), deliver_payload)
    }

    for user_ws in local_users.values():
        try:
            await user_ws.send(json.dumps(deliver_msg))
        except:
            pass

async def handle_command(websocket: websockets.WebSocketServerProtocol, msg: ProtocolMessage):
    """Handle user commands like /list, /tell, /all"""
    parts = msg.type.split()
    if not parts:
        return

    cmd = parts[0]

    if cmd == "/list":
        # Return list of online users
        online_users = list(user_locations.keys())
        response = {
            "type": "COMMAND_RESPONSE",
            "from": server_id,
            "to": msg.from_,
            "ts": current_timestamp(),
            "payload": {"command": "list", "users": online_users},
            "sig": ""  # TODO
        }
        await websocket.send(json.dumps(response))

    elif cmd == "/tell" and len(parts) >= 3:
        # DM: /tell <user> <message>
        target_user = parts[1]
        message_text = " ".join(parts[2:])

        # Encrypt message
        target_data = db.get_user(target_user)
        if not target_data:
            return

        sender_data = db.get_user(msg.from_)
        if not sender_data:
            return

        sender_priv_key = load_private_key(sender_data["privkey_store"])  # TODO: decrypt
        target_pub_key = load_public_key(target_data["pubkey"])

        ciphertext = rsa_encrypt(target_pub_key, message_text.encode('utf-8'))
        content_sig = compute_content_sig(sender_priv_key, ciphertext, msg.from_, target_user, msg.ts)

        dm_payload = {
            "ciphertext": ciphertext,
            "sender_pub": sender_data["pubkey"],
            "content_sig": content_sig
        }

        dm_msg = {
            "type": "MSG_DIRECT",
            "from": msg.from_,
            "to": target_user,
            "ts": current_timestamp(),
            "payload": dm_payload,
            "sig": ""  # Optional for user messages
        }

        await handle_msg_direct(ProtocolMessage(**dm_msg))

    elif cmd == "/all" and len(parts) >= 2:
        # Public message: /all <message>
        message_text = " ".join(parts[1:])

        # For simplicity, send unencrypted (should be encrypted with group key)
        pub_payload = {
            "ciphertext": message_text,  # TODO: encrypt with group key
            "sender_pub": db.get_user(msg.from_)["pubkey"],
            "content_sig": ""  # TODO
        }

        pub_msg = {
            "type": "MSG_PUBLIC_CHANNEL",
            "from": msg.from_,
            "to": "public",
            "ts": current_timestamp(),
            "payload": pub_payload,
            "sig": ""
        }

        await handle_msg_public_channel(ProtocolMessage(**pub_msg))

async def main():
    """Main server function"""
    init_server()

    # Start WebSocket server
    server = await websockets.serve(
        handle_connection,
        config.host,
        config.port,
        ping_interval=None,  # Disable ping/pong for simplicity
        ping_timeout=None
    )

    logger.info(f"WebSocket server started on ws://{config.host}:{config.port}/ws")

    # Bootstrap to network if not introducer
    if not config.is_introducer:
        await asyncio.sleep(1)  # Give server time to start
        await bootstrap_to_network()

    # Keep server running
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
