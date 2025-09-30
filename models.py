from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import uuid
import time

class ProtocolMessage(BaseModel):
    type: str
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: Optional[str] = None

    class Config:
        populate_by_name = True

# Server to Server Messages
class ServerHelloJoinPayload(BaseModel):
    host: str
    port: int
    pubkey: str

class ServerWelcomePayload(BaseModel):
    assigned_id: str
    clients: List[Dict[str, str]]  # [{"user_id": "", "host": "", "port": "", "pubkey": ""}]

class ServerAnnouncePayload(BaseModel):
    host: str
    port: int
    pubkey: str

class UserAdvertisePayload(BaseModel):
    user_id: str
    server_id: str
    pubkey: str
    meta: Optional[Dict[str, Any]] = None

class UserRemovePayload(BaseModel):
    user_id: str
    server_id: str

class ServerDeliverPayload(BaseModel):
    user_id: str
    ciphertext: str
    sender: str
    sender_pub: str
    content_sig: str

class HeartbeatPayload(BaseModel):
    pass

# User to Server Messages
class UserHelloPayload(BaseModel):
    client: str
    pubkey: str
    enc_pubkey: Optional[str] = None

class MsgDirectPayload(BaseModel):
    ciphertext: str
    sender_pub: str
    content_sig: str

class MsgPublicChannelPayload(BaseModel):
    ciphertext: str
    sender_pub: str
    content_sig: str

class PublicChannelAddPayload(BaseModel):
    add: List[str]
    if_version: int

class PublicChannelUpdatedPayload(BaseModel):
    version: int
    wraps: List[Dict[str, str]]  # [{"member_id": "", "wrapped_key": ""}]

class PublicChannelKeySharePayload(BaseModel):
    shares: List[Dict[str, str]]  # [{"member": "", "wrapped_public_channel_key": ""}]
    creator_pub: str
    content_sig: str

class FileStartPayload(BaseModel):
    file_id: str
    name: str
    size: int
    sha256: str
    mode: str  # "dm" or "public"

class FileChunkPayload(BaseModel):
    file_id: str
    index: int
    ciphertext: str

class FileEndPayload(BaseModel):
    file_id: str

class AckPayload(BaseModel):
    msg_ref: str

class ErrorPayload(BaseModel):
    code: str
    detail: str

# User Deliver (Server to User)
class UserDeliverPayload(BaseModel):
    ciphertext: str
    sender: str
    sender_pub: str
    content_sig: str

def generate_uuid() -> str:
    return str(uuid.uuid4())

def current_timestamp() -> int:
    return int(time.time() * 1000)
