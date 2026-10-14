"""
Tier 0: deterministic policy.

Fast, fully auditable allow and deny rules keyed on the action type and target.
This is the Parallax Tier 0 idea: the cheapest, most predictable mechanism
handles the clear cut cases. Anything that does not match a rule falls through
to the heuristics tier.

Rules are ordered: deny wins, then verify (escalate to a higher tier), then
allow. No match means "undecided", and the broker takes it to Tier 1.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import List, Optional

from .action import Action, ActionType, Verdict

# Paths that are always off limits, regardless of how the request is framed.
SENSITIVE_DENY = [
    "*/.ssh/*", "*/.aws/*", "*/etc/shadow", "*/etc/passwd",
    "*.pem", "*id_rsa*",
]

# The broker's own files. Reads blocked, writes blocked. This is the
# self protection layer: the agent cannot read or rewrite the thing judging it.
SELF_PROTECT = [
    "*/airlock/*.py", "*audit.log", "*policy*.py", "*.chronicle/*",
]


@dataclass
class Rule:
    name: str
    verdict: Verdict
    action_types: List[ActionType]
    patterns: List[str]
    tier_override: Optional[int] = None

    def matches(self, action: Action) -> bool:
        if action.type not in self.action_types:
            return False
        if not self.patterns:
            return True
        return any(fnmatch.fnmatch(action.target, p) for p in self.patterns)


DEFAULT_RULES: List[Rule] = [
    Rule(
        name="block_path_traversal",
        verdict=Verdict.DENY,
        action_types=[ActionType.READ_FILE, ActionType.WRITE_FILE,
                      ActionType.DELETE_FILE],
        patterns=["*..*"],
    ),
    Rule(
        name="self_protection",
        verdict=Verdict.DENY,
        action_types=[ActionType.WRITE_FILE, ActionType.DELETE_FILE,
                      ActionType.READ_FILE],
        patterns=SELF_PROTECT,
    ),
    Rule(
        name="block_sensitive_paths",
        verdict=Verdict.DENY,
        action_types=[ActionType.READ_FILE, ActionType.WRITE_FILE,
                      ActionType.DELETE_FILE],
        patterns=SENSITIVE_DENY,
    ),
    # Shell and outbound actions always get a deeper look.
    Rule(
        name="inspect_commands",
        verdict=Verdict.ESCALATE,
        action_types=[ActionType.EXECUTE_COMMAND],
        patterns=[],
        tier_override=1,
    ),
    Rule(
        name="inspect_outbound",
        verdict=Verdict.ESCALATE,
        action_types=[ActionType.HTTP_REQUEST, ActionType.SEND_EMAIL],
        patterns=[],
        tier_override=1,
    ),
    # Deletes are reversible via Chronicle, but still worth a human nod.
    Rule(
        name="inspect_deletes",
        verdict=Verdict.ESCALATE,
        action_types=[ActionType.DELETE_FILE],
        patterns=[],
        tier_override=1,
    ),
    # Plain reads and listings inside the workspace are fine.
    Rule(
        name="allow_workspace_reads",
        verdict=Verdict.PERMIT,
        action_types=[ActionType.READ_FILE, ActionType.LIST_DIR],
        patterns=["*"],
    ),
]


class Tier0Policy:
    def __init__(self, rules: Optional[List[Rule]] = None) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES

    def evaluate(self, action: Action) -> Optional[tuple]:
        """Return (verdict, rule_name, tier_override) or None if undecided."""
        for rule in self.rules:
            if rule.matches(action):
                return (rule.verdict, rule.name, rule.tier_override)
        return None
