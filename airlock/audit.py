"""
Audit log with a tamper evident hash chain.

Every decision the broker makes is written here, chained so that altering any
past entry breaks every entry after it. This is the accountability half, shared
by both papers: SMCP signs and chains audit entries, Parallax keeps an append
only log the agent cannot touch.

Each entry carries the hash of the previous one, plus an HMAC keyed on a secret
the agent never sees. verify() walks the chain and reports the first break.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from typing import List


class AuditLog:
    def __init__(self, path: Path, secret: bytes) -> None:
        self.path = Path(path)
        self.secret = secret
        self.entries: List[dict] = []
        self._prev = "0" * 64

    def append(self, context, action, decision) -> dict:
        body = {
            "ts": round(time.time(), 3),
            "call_chain_id": context.call_chain_id,
            "actor": context.delegation_chain[-1].identity_code,
            "delegation": [p.identity_code for p in context.delegation_chain],
            "risk": context.risk_level.value,
            "sensitivity": context.data_sensitivity.value,
            "action": action.type.value,
            "target": action.target,
            "verdict": decision.verdict.value,
            "tier": decision.tier,
            "reason": decision.reason,
            "obligations": decision.obligations,
            "prev": self._prev,
        }
        canonical = json.dumps(body, sort_keys=True)
        entry_hash = hashlib.sha256((self._prev + canonical).encode()).hexdigest()
        sig = hmac.new(self.secret, entry_hash.encode(), hashlib.sha256).hexdigest()
        body["hash"] = entry_hash
        body["sig"] = sig
        self.entries.append(body)
        self._prev = entry_hash
        self._flush(body)
        return body

    def _flush(self, body: dict) -> None:
        with self.path.open("a") as fh:
            fh.write(json.dumps(body) + "\n")

    def verify(self) -> tuple:
        """Return (ok, message). Walks the chain from the start."""
        prev = "0" * 64
        for i, body in enumerate(self.entries):
            check = {k: v for k, v in body.items() if k not in ("hash", "sig")}
            canonical = json.dumps(check, sort_keys=True)
            expect = hashlib.sha256((prev + canonical).encode()).hexdigest()
            if expect != body["hash"]:
                return (False, f"entry {i} hash mismatch, chain broken here")
            expect_sig = hmac.new(self.secret, expect.encode(),
                                  hashlib.sha256).hexdigest()
            if expect_sig != body["sig"]:
                return (False, f"entry {i} signature invalid")
            prev = body["hash"]
        return (True, f"{len(self.entries)} entries verified, chain intact")
