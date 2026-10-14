"""
The broker: the trusted gateway between reasoning and execution.

Every action the agent proposes arrives here. The broker runs it through the
tiers in order, in increasing cost and decreasing determinism, and only a
permissive verdict reaches the executor. The agent holds no execution
capability of its own, so a fully compromised agent can still only ever
propose; the broker decides.

Evaluation order:
  Tier 0   deterministic policy (allow and deny rules, self protection)
  flow     information flow control (restricted data leaving the boundary)
  prov     provenance (executing an agent authored file)
  Tier 1   heuristic pattern scan on commands and payloads
  Tier 2   optional human or model evaluator for what is left ambiguous

Fail closed: if anything raises, the action is denied.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Callable, Optional

from . import ifc, provenance
from .action import Action, ActionType, Decision, Verdict
from .audit import AuditLog
from .chronicle import Chronicle
from .heuristics import Tier1Heuristics
from .identity import RiskLevel, SecurityContext
from .policy import Tier0Policy
from .tools import Executor

DESTRUCTIVE = {ActionType.WRITE_FILE, ActionType.DELETE_FILE}


class Broker:
    def __init__(self, workspace: Path,
                 human_approver: Optional[Callable[[Action], bool]] = None) -> None:
        self.workspace = Path(workspace)
        self.policy = Tier0Policy()
        self.heuristics = Tier1Heuristics()
        self.executor = Executor(self.workspace)
        self.chronicle = Chronicle(self.workspace / ".chronicle")
        self.audit = AuditLog(self.workspace / "audit.log", secret=secrets.token_bytes(32))
        self.human_approver = human_approver

    # ---- validation ---------------------------------------------------

    def evaluate(self, context: SecurityContext, action: Action) -> Decision:
        try:
            return self._evaluate(context, action)
        except Exception as exc:  # fail closed
            return Decision(Verdict.DENY, tier=-1, reason=f"evaluation error: {exc}")

    def _evaluate(self, context: SecurityContext, action: Action) -> Decision:
        # Tier 0
        result = self.policy.evaluate(action)
        escalated = False
        if result is not None:
            verdict, rule_name, override = result
            if verdict == Verdict.DENY:
                return Decision(Verdict.DENY, 0, f"policy rule {rule_name!r}")
            if verdict == Verdict.PERMIT:
                return self._clear(context, action, 0, f"policy rule {rule_name!r}")
            if verdict == Verdict.ESCALATE:
                escalated = True

        # Information flow control
        flow = ifc.check_flow(context, action)
        if flow:
            return Decision(Verdict.DENY, 1, f"information flow: {flow}")

        # Provenance
        prov = provenance.check_execution(context, action)
        if prov:
            return Decision(Verdict.DENY, 1, f"provenance: {prov}")

        # Tier 1
        hit = self.heuristics.scan(action)
        if hit:
            return Decision(Verdict.DENY, 1, f"heuristic: {hit.label}")

        # Tier 2 and 3 for whatever Tier 0 flagged as needing a deeper look
        # and that the deterministic tiers did not resolve either way.
        if escalated:
            if self.human_approver is not None:
                approved = self.human_approver(action)
                if approved:
                    return self._clear(context, action, 3, "human approved")
                return Decision(Verdict.DENY, 3, "human denied")
            # No human wired up: stay safe, do not guess.
            return Decision(Verdict.DENY, 2, "ambiguous, no approver available, denied closed")

        return self._clear(context, action, 1, "passed all deterministic checks")

    def _clear(self, context, action, tier, reason) -> Decision:
        return Decision(Verdict.PERMIT, tier, reason)

    # ---- execution ----------------------------------------------------

    def submit(self, context: SecurityContext, action: Action):
        """Validate, log, and if permitted execute. Returns (decision, result)."""
        decision = self.evaluate(context, action)
        self.audit.append(context, action, decision)

        if not decision.allowed:
            return decision, None

        if action.type in DESTRUCTIVE:
            self.chronicle.capture(self.executor._resolve(action.target),
                                   reason=action.type.value)

        result = self.executor.run(action)

        # Post execution bookkeeping the broker owns.
        if action.type == ActionType.READ_FILE:
            ifc.record_read(context, action.target, result or "")
        if action.type == ActionType.WRITE_FILE:
            provenance.record_write(context, action.target)

        return decision, result
