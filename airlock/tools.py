"""
Tool executors.

These are the only functions in the whole system that touch the world, and
nothing but the broker is allowed to call them. Everything runs inside a single
workspace directory so the demo can never escape onto the real machine.

In a faithful deployment this module lives in a separate OS process from the
agent, reachable only over a narrow channel. The demo keeps it in process for
readability, and the test in tests_separation.py asserts that the agent module
never imports it. See the README for the honest note on this.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .action import Action, ActionType


class Executor:
    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)

    def _resolve(self, target: str) -> Path:
        p = (self.workspace / target).resolve()
        if self.workspace.resolve() not in p.parents and p != self.workspace.resolve():
            raise PermissionError(f"path escapes workspace: {target}")
        return p

    def run(self, action: Action) -> str:
        if action.type == ActionType.READ_FILE:
            return self._resolve(action.target).read_text()
        if action.type == ActionType.WRITE_FILE:
            p = self._resolve(action.target)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(action.payload)
            return f"wrote {len(action.payload)} bytes"
        if action.type == ActionType.DELETE_FILE:
            self._resolve(action.target).unlink()
            return "deleted"
        if action.type == ActionType.LIST_DIR:
            base = self._resolve(action.target or ".")
            return "\n".join(sorted(x.name for x in base.iterdir()))
        if action.type == ActionType.EXECUTE_COMMAND:
            out = subprocess.run(action.payload, shell=True, cwd=self.workspace,
                                 capture_output=True, text=True, timeout=10)
            return out.stdout + out.stderr
        if action.type in (ActionType.HTTP_REQUEST, ActionType.SEND_EMAIL):
            # Simulated. The demo never makes real outbound calls.
            return f"[simulated] {action.type.value} to {action.target}"
        raise ValueError(f"unknown action {action.type}")
