"""
Identity and security context.

This brings the SMCP ideas down to a small, runnable form: every principal
(user, agent, tool) carries a structured identity, and every request the
broker evaluates is wrapped in a security context that records the full
delegation chain, the risk level and the sensitivity of data seen so far.

The key design choice, and a deliberate departure from a naive agent: the
security context is built and owned by the broker, never by the agent. A
compromised agent cannot lower its own risk level or forge its delegation
chain, because it never gets to write these fields.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import List


class PrincipalType(str, Enum):
    USER = "US"
    AGENT = "AG"
    TOOL = "TL"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


_ORDER = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.RESTRICTED: 3,
}


def highest(a: Sensitivity, b: Sensitivity) -> Sensitivity:
    return a if _ORDER[a] >= _ORDER[b] else b


@dataclass
class Principal:
    """A registered actor. The id is a short structured code, loosely modelled
    on the SMCP identity code (type + random serial)."""

    kind: PrincipalType
    name: str
    role: str
    identity_code: str = ""

    def __post_init__(self) -> None:
        if not self.identity_code:
            serial = secrets.token_hex(6).upper()
            self.identity_code = f"{self.kind.value}01{serial}"


@dataclass
class SecurityContext:
    """Travels with every proposed action. Owned by the broker."""

    call_chain_id: str
    session_id: str
    delegation_chain: List[Principal]
    risk_level: RiskLevel = RiskLevel.LOW
    data_sensitivity: Sensitivity = Sensitivity.PUBLIC

    # Runtime state the broker accumulates and the agent cannot touch.
    tainted_values: set = field(default_factory=set)      # information flow control
    agent_authored_files: set = field(default_factory=set)  # provenance tracking

    def has_verified_human(self) -> bool:
        return any(p.kind == PrincipalType.USER for p in self.delegation_chain)


def new_context(user: Principal, agent: Principal) -> SecurityContext:
    return SecurityContext(
        call_chain_id="CC-" + secrets.token_hex(8),
        session_id="S-" + secrets.token_hex(8),
        delegation_chain=[user, agent],
    )
