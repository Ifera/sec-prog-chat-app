import asyncio
import json
import sys
import websockets
from websockets.exceptions import ConnectionClosedError

from crypto import *
from models import *

class SOCPClient:
    def __init__(self, server_host: str = "localhost", server_port: int = 8082):
        self.server_uri = f"ws://{server_host}:{server_port}/ws"
        self.user_id = None
        self.private_key = None
        self.public_key = None
        self.websocket = None

    def init_user(self, user_id: str = None):
        """Initialize user with RSA keys"""
        if user_id:
            self.user_id = user_id
        else:
            self.user_id = generate_uuid()

        self.private_key, self.public_key = generate_rsa_keypair()
        print(f"User initialized with ID: {self.user_id}")

    async def connect(self):
        """Connect to the server"""
        try:
            self.websocket = await websockets.connect(self.server_uri)
            print(f"Connected to server at {self.server_uri}")

            # Send USER_HELLO
            hello_payload = {
                "client": "socp-client-v1.0",
                "pubkey": self.public_key
            }
            hello_msg = {
                "type": "USER_HELLO",
                "from_": self.user_id,
                "to": "server",  # Server will be identified later
                "ts": current_timestamp(),
                "payload": hello_payload,
                "sig": ""  # Optional for hello
            }

            await self.websocket.send(json.dumps(hello_msg))
            print("Sent USER_HELLO")

            # Start listening for messages
            await self.listen()

        except Exception as e:
            print(f"Connection failed: {e}")

    async def listen(self):
        """Listen for incoming messages"""
        try:
            async for message in self.websocket:
                data = json.loads(message)
                await self.handle_message(data)
        except ConnectionClosedError:
            print("Connection closed")
        except Exception as e:
            print(f"Error receiving message: {e}")

    async def handle_message(self, data: dict):
        """Handle incoming messages"""
        msg_type = data.get("type")

        if msg_type == "USER_DELIVER":
            await self.handle_user_deliver(data)
        elif msg_type == "COMMAND_RESPONSE":
            await self.handle_command_response(data)
        elif msg_type == "ERROR":
            print(f"Error: {data['payload']}")
        else:
            print(f"Received: {data}")

    async def handle_user_deliver(self, data: dict):
        """Handle USER_DELIVER message"""
        payload = data["payload"]

        try:
            # Decrypt the message
            ciphertext = payload["ciphertext"]
            sender_pub = payload["sender_pub"]

            # Load sender's public key
            sender_pub_key = load_public_key(sender_pub)

            # Verify content signature
            content_sig_valid = verify_content_sig(
                sender_pub_key,
                ciphertext,
                data["from"],  # sender
                data["to"],    # recipient (should be us)
                data["ts"],
                payload["content_sig"]
            )

            if not content_sig_valid:
                print("Warning: Content signature verification failed")

            # Decrypt
            plaintext = rsa_decrypt(load_private_key(self.private_key), ciphertext)
            message_text = plaintext.decode('utf-8')

            print(f"[{payload['sender']}] {message_text}")

        except Exception as e:
            print(f"Failed to decrypt message: {e}")

    async def handle_command_response(self, data: dict):
        """Handle COMMAND_RESPONSE"""
        payload = data["payload"]
        cmd = payload.get("command")

        if cmd == "list":
            users = payload.get("users", [])
            print(f"Online users: {', '.join(users)}")

    async def send_command(self, command: str):
        """Send a command to the server"""
        msg = {
            "type": command,
            "from_": self.user_id,
            "to": "server",
            "ts": current_timestamp(),
            "payload": {},
            "sig": ""
        }
        await self.websocket.send(json.dumps(msg))

    async def send_message(self, message_type: str, payload: dict):
        """Send a message to the server"""
        msg = {
            "type": message_type,
            "from_": self.user_id,
            "to": payload.get("to", "server"),
            "ts": current_timestamp(),
            "payload": payload,
            "sig": ""
        }
        await self.websocket.send(json.dumps(msg))

async def interactive_client():
    """Run an interactive client"""
    if len(sys.argv) > 1:
        user_id = sys.argv[1]
    else:
        user_id = None

    client = SOCPClient()
    client.init_user(user_id)

    # Connect in background
    connect_task = asyncio.create_task(client.connect())

    # Wait a bit for connection
    await asyncio.sleep(2)

    print("Commands:")
    print("  /list              - List online users")
    print("  /tell <user> <msg> - Send DM to user")
    print("  /all <msg>         - Send public message")
    print("  /quit              - Exit")
    print()

    while True:
        try:
            line = await asyncio.get_event_loop().run_in_executor(None, input, "> ")
            line = line.strip()

            if not line:
                continue

            if line == "/quit":
                break

            await client.send_command(line)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")

    # Close connection
    if client.websocket:
        await client.websocket.close()

if __name__ == "__main__":
    asyncio.run(interactive_client())
