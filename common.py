import time
from dataclasses import dataclass, field
from typing import Union, Optional

from websockets import ClientConnection, ServerConnection


@dataclass
class Peer:
    sid: str
    ws: Union[ClientConnection, ServerConnection]
    host: str
    port: int
    pubkey: Optional[str] = None
    last_seen: float = field(default_factory=lambda: time.time())
    missed: int = 0
