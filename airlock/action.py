"""
The vocabulary shared between the agent and the broker.

An Action is what the agent proposes. It is pure data. It carries no ability
to do anything on its own; only the broker's executor can act on it, and only
after the broker returns a permissive decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(str, Enum):
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    DELETE_FILE = "delete_file"
    LIST_DIR = "list_directory"
    EXECUTE_COMMAND = "execute_command"
    HTTP_REQUEST = "http_request"
    SEND_EMAIL = "send_email"


class Verdict(str, Enum):
    PERMIT = "PERMIT"
    PERMIT_WITH_OBLIGATIONS = "PERMIT_WITH_OBLIGATIONS"
    DENY = "DENY"
    ESCALATE = "ESCALATE"  # hand to a human


@dataclass
class Action:
    type: ActionType
    target: str = ""
    payload: str = ""
    args: Dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        t = self.target or "-"
        p = (self.payload[:40] + "...") if len(self.payload) > 40 else self.payload
        return f"{self.type.value} target={t} payload={p!r}"


@dataclass
class Decision:
    verdict: Verdict
    tier: int                 # which tier resolved it (0..3)
    reason: str
    obligations: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict in (Verdict.PERMIT, Verdict.PERMIT_WITH_OBLIGATIONS)
