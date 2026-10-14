"""
File provenance tracking.

This is the piece the two papers leave open. Parallax says plainly that it
evaluates the command that runs a script but does not read the script's
contents, so an agent can write a malicious file (a permitted write) and then
execute it (a permitted command), and the harmful logic is never inspected.

The fix here is to track which files the agent itself authored during the
session. If the agent later tries to execute a file it wrote, the broker treats
that as high risk and refuses, because the broker never got to validate the
logic inside. A human can still approve it, but it does not pass silently.

This is deliberately simple. It does not try to parse the script. It changes
the trust posture based on where the file came from, which is the honest signal
the broker actually has.
"""

from __future__ import annotations

import re
from typing import Optional

from .action import Action, ActionType


def record_write(context, path: str) -> None:
    """Remember that the agent authored this path."""
    context.agent_authored_files.add(_norm(path))


def check_execution(context, action: Action) -> Optional[str]:
    """Return a reason to block if the command runs an agent authored file."""
    if action.type != ActionType.EXECUTE_COMMAND:
        return None
    cmd = " ".join([action.target, action.payload])
    for authored in context.agent_authored_files:
        name = authored.split("/")[-1]
        if name and re.search(rf"\b{re.escape(name)}\b", cmd):
            return f"command executes agent authored file {name!r}, contents never validated"
    return None


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip()
