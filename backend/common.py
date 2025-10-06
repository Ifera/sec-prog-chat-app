import json
import time
from dataclasses import dataclass, field
from typing import Union, Optional

from websockets import ClientConnection, ServerConnection

from models import current_timestamp, MsgType


@dataclass
class Peer:
    sid: str
    ws: Union[ClientConnection, ServerConnection]
    host: str
    port: int
    pubkey: Optional[str] = None
    last_seen: float = field(default_factory=lambda: time.time())
    missed: int = 0
    outbound: bool = False


def create_body(typ: MsgType, frm: str, to: str, payload: dict, sig: str = "", ts: int | None = None) -> str:
    req = {
        "type": typ.value,
        "from": frm,
        "to": to,
        "ts": ts if ts is not None else current_timestamp(),
        "payload": payload,
        "sig": sig
    }
    return json.dumps(req)
