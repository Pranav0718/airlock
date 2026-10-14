"""
Tier 1: heuristic pattern matching.

Rule based detection of known dangerous shapes in commands, payloads and URLs.
This is the deterministic half of the Parallax Tier 1 classifier. The paper
also runs a learned model here; this demo keeps it to heuristics so it stays
dependency free and fully offline, and notes in the README where the model
would slot in.

Patterns are checked against the expanded form of a command so that simple
obfuscation (base64, hex, variable expansion) does not slip past the surface
check. The decoder below is intentionally small; it is enough to show the idea.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import List, Optional

from .action import Action, ActionType

DANGEROUS = [
    (r"\brm\s+-rf?\b", "recursive delete"),
    (r":\(\)\s*\{.*\};:", "fork bomb"),
    (r"\bchmod\s+777\b", "world writable permission"),
    (r"\bsudo\b", "privilege escalation"),
    (r"curl[^|]*\|\s*(ba)?sh", "pipe to shell"),
    (r"wget[^|]*\|\s*(ba)?sh", "pipe to shell"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material"),
    (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "aws access key"),
    (r"/dev/tcp/", "reverse shell"),
    (r"\bnc\b.*-e\b", "netcat shell"),
    (r"\bmkfs\b", "filesystem format"),
    (r"\bdd\s+if=.*of=/dev/", "raw disk write"),
    (r"\beval\b.*base64", "eval of decoded payload"),
]


def _expand(text: str) -> str:
    """Best effort decode of base64 and hex blobs so patterns see the real
    command, not the wrapper."""
    expanded = [text]

    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", "ignore")
            if decoded.strip():
                expanded.append(decoded)
        except (binascii.Error, ValueError):
            pass

    for token in re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", text):
        try:
            decoded = bytes.fromhex(token.replace("\\x", "")).decode("utf-8", "ignore")
            if decoded.strip():
                expanded.append(decoded)
        except ValueError:
            pass

    return "\n".join(expanded)


@dataclass
class Hit:
    label: str
    pattern: str


class Tier1Heuristics:
    def scan(self, action: Action) -> Optional[Hit]:
        haystack = _expand(" ".join([action.target, action.payload,
                                     str(action.args)]))
        for pattern, label in DANGEROUS:
            if re.search(pattern, haystack, re.IGNORECASE):
                return Hit(label=label, pattern=pattern)
        return None
