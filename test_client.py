import asyncio
import json
import websockets

from crypto import *
from models import *

async def test_client():
    """Test client that sends commands automatically"""
    # Connect to server
    uri = "ws://localhost:8080/ws"
    user_id = "test_user"

    # Generate keys
    private_key, public_key = generate_rsa_keypair()

    try:
        async with websockets.connect(uri) as websocket:
            print("Connected to server")

            # Send USER_HELLO
            hello_payload = {
                "client": "test-client",
                "pubkey": public_key
            }
            hello_msg = {
                "type": "USER_HELLO",
                "from_": user_id,
                "to": "server",  # Server will be identified later
                "ts": current_timestamp(),
                "payload": hello_payload,
                "sig": ""  # Optional for hello
            }

            await websocket.send(json.dumps(hello_msg))
            print("Sent USER_HELLO")

            # Wait a bit for server response
            await asyncio.sleep(1)

            # Send /list command
            list_msg = {
                "type": "/list",
                "from_": user_id,
                "to": "server",
                "ts": current_timestamp(),
                "payload": {},
                "sig": ""
            }

            await websocket.send(json.dumps(list_msg))
            print("Sent /list command")

            # Listen for responses
            try:
                async for message in websocket:
                    data = json.loads(message)
                    print(f"Received: {data}")

                    # If we got the list response, send a test message
                    if data.get("type") == "COMMAND_RESPONSE" and data["payload"].get("command") == "list":
                        print("List command worked! Users online:", data["payload"].get("users", []))

                        # Send a test public message
                        all_msg = {
                            "type": "/all Hello from test client!",
                            "from_": user_id,
                            "to": "server",
                            "ts": current_timestamp(),
                            "payload": {},
                            "sig": ""
                        }

                        await websocket.send(json.dumps(all_msg))
                        print("Sent public message")

                        # Wait a bit then quit
                        await asyncio.sleep(2)
                        break

            except Exception as e:
                print(f"Error receiving: {e}")

    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_client())
