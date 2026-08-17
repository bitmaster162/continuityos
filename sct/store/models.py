from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class EventRecord:
    seq: int
    event_id: str
    kind: str
    ts: float
    payload: Mapping[str, Any]
    prev_hash: Optional[str]
    event_hash: str


@dataclass(frozen=True)
class ChainHead:
    seq: int
    event_hash: Optional[str]


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    head_hash: Optional[str]
    error: Optional[str] = None
