"""
The agent side.

This module stands in for the reasoning system. The whole point of the
architecture is in what is NOT here: this file does not import the executor,
the tools, or anything that touches the filesystem or the network. It can only
build Action objects and hand them to the broker.

A real deployment would put an LLM behind propose(), and would run this module
in a separate sandboxed process. The demo keeps it as a simple scripted planner
so the behaviour is reproducible offline, and so the attack harness can inject
arbitrary proposed actions to simulate a fully compromised agent (the
assume compromise method from the Parallax paper).

Grep this file: there is no 'import' of airlock.tools or airlock.broker. That
absence is the cognitive executive separation, made checkable.
"""

from __future__ import annotations

from typing import List

from airlock.action import Action, ActionType


class Planner:
    """Turns a goal into a list of proposed actions. Proposes only."""

    def plan(self, goal: str) -> List[Action]:
        goal = goal.lower()
        if "summar" in goal and "report" in goal:
            return [
                Action(ActionType.READ_FILE, target="report.txt"),
                Action(ActionType.WRITE_FILE, target="summary.txt",
                       payload="Short summary of the report."),
            ]
        if "list" in goal:
            return [Action(ActionType.LIST_DIR, target=".")]
        # Default: do nothing rather than improvise an action.
        return []
