from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Optional, Dict, Any, List

from pydantic import BaseModel, Field


class MsgType(StrEnum):
    # Server <-> Server
    FILE_START = "FILE_START"
    FILE_CHUNK = "FILE_CHUNK"
    FILE_END = "FILE_END"
    SERVER_HELLO_JOIN = "SERVER_HELLO_JOIN"
    SERVER_WELCOME = "SERVER_WELCOME"
    SERVER_ANNOUNCE = "SERVER_ANNOUNCE"
    SERVER_GOODBYE = "SERVER_GOODBYE"
    USER_ADVERTISE = "USER_ADVERTISE"
    USER_REMOVE = "USER_REMOVE"
    SERVER_DELIVER = "SERVER_DELIVER"
    HEARTBEAT = "HEARTBEAT"
    ACK = "ACK"
    ERROR = "ERROR"

    # User <-> Server
    USER_HELLO = "USER_HELLO"
    USER_DELIVER = "USER_DELIVER"
    MSG_DIRECT = "MSG_DIRECT"
    MSG_PUBLIC_CHANNEL = "MSG_PUBLIC_CHANNEL"
    PUBLIC_CHANNEL_ADD = "PUBLIC_CHANNEL_ADD"
    PUBLIC_CHANNEL_UPDATED = "PUBLIC_CHANNEL_UPDATED"
    PUBLIC_CHANNEL_KEY_SHARE = "PUBLIC_CHANNEL_KEY_SHARE"
    COMMAND = "COMMAND"
    COMMAND_RESPONSE = "COMMAND_RESPONSE"


class ErrorCode(StrEnum):
    USER_NOT_FOUND = "USER_NOT_FOUND"
    INVALID_SIG = "INVALID_SIG"
    BAD_KEY = "BAD_KEY"
    TIMEOUT = "TIMEOUT"
    UNKNOWN_TYPE = "UNKNOWN_TYPE"
    NAME_IN_USE = "NAME_IN_USE"
    FILE_TOO_BIG = "FILE_TOO_BIG"


class ProtocolMessage(BaseModel):
    type: MsgType
    from_: str = Field(alias="from")
    to: str
    ts: int
    payload: Dict[str, Any]
    sig: Optional[str] = None

    class Config:
        populate_by_name = True


# Server <-> Server Messages
class ServerHelloJoinPayload(BaseModel):
    host: str
    port: int
    pubkey: str


class ServerInfo(BaseModel):
    server_id: str
    host: str
    port: int
    pubkey: str


class ClientInfo(BaseModel):
    user_id: str
    host: str
    port: int
    pubkey: str
    server_id: str


class ServerWelcomePayload(BaseModel):
    assigned_id: str
    servers: List[ServerInfo]
    clients: List[ClientInfo]


class ServerAnnouncePayload(BaseModel):
    host: str
    port: int
    pubkey: str


class ServerGoodbyePayload(BaseModel):
    reason: str = "shutdown"


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


class ServerType(StrEnum):
    INTRODUCER = "INTRODUCER"
    SERVER = "SERVER"


class HeartbeatPayload(BaseModel):
    server_type: ServerType


# User <-> Server Messages
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


class CommandPayload(BaseModel):
    command: str


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


class AckPayload(BaseModel):
    msg_ref: str


class ErrorPayload(BaseModel):
    code: ErrorCode
    detail: str


class UserDeliverPayload(BaseModel):
    ciphertext: str
    sender: str
    sender_pub: str
    content_sig: str


class CommandResponsePayload(BaseModel):
    command: str
    response: str


class FileStartPayload(BaseModel):
    file_id: str
    name: str
    size: int
    sha256: str
    mode: str


class FileChunkPayload(BaseModel):
    file_id: str
    index: int
    ciphertext: str


class FileEndPayload(BaseModel):
    file_id: str


def generate_uuid() -> str:
    return str(uuid.uuid4())


def current_timestamp() -> int:
    return int(time.time() * 1000)
