"""
Information flow control.

This is the Parallax Principle 3 idea. Data picks up a sensitivity label at the
point it is read. The label, and the actual secret value, follow the session.
When the agent later tries to push that value toward an outbound sink (an
http request, an email), the broker sees the flow and blocks it, no matter how
many benign looking steps separated the read from the send.

Action level validation alone cannot catch this: reading a file is fine, making
a request is fine, but the sequence exfiltrates a secret. IFC catches the
sequence.
"""

from __future__ import annotations

import re
from typing import Optional

from .action import Action, ActionType
from .identity import Sensitivity

# Sources whose contents are treated as restricted the moment they are read.
RESTRICTED_SOURCES = [
    r"\.env($|\.)", r"\.pem$", r"credential", r"secret", r"\.ssh/",
    r"\.aws/", r"id_rsa", r"token", r"password",
]

# Where tainted data must never go.
OUTBOUND = {ActionType.HTTP_REQUEST, ActionType.SEND_EMAIL}


def classify_source(path: str) -> Sensitivity:
    for pat in RESTRICTED_SOURCES:
        if re.search(pat, path, re.IGNORECASE):
            return Sensitivity.RESTRICTED
    return Sensitivity.INTERNAL


def record_read(context, path: str, content: str) -> None:
    """Called by the broker after a permitted read. Labels the session and
    remembers the secret values so later outbound actions can be checked."""
    label = classify_source(path)
    context.data_sensitivity = _max(context.data_sensitivity, label)
    if label == Sensitivity.RESTRICTED:
        for line in content.splitlines():
            value = line.split("=", 1)[-1].strip().strip('"').strip("'")
            if len(value) >= 6:
                context.tainted_values.add(value)


def check_flow(context, action: Action) -> Optional[str]:
    """Return a violation reason if this action would move restricted data out,
    else None."""
    if action.type not in OUTBOUND:
        return None
    blob = " ".join([action.target, action.payload, str(action.args)])
    for secret in context.tainted_values:
        if secret and secret in blob:
            return "restricted data would leave the trust boundary"
    return None


def _max(a: Sensitivity, b: Sensitivity) -> Sensitivity:
    from .identity import highest
    return highest(a, b)
