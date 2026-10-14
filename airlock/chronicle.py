"""
Chronicle: reversible execution.

Parallax Principle 4. Before any destructive action the broker snapshots the
affected file, so that if the action turns out to be harmful after the fact it
can be rolled back. No action inside the workspace is truly irreversible.

Snapshots are content addressed and tied to the action that triggered them.
This cannot undo actions with external side effects (a sent email, a network
call), which is exactly why those actions lean harder on the pre execution
checks.
"""

from __future__ import annotations

import hashlib
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class Snapshot:
    original_path: str
    stored_path: Optional[str]
    existed: bool
    timestamp: float
    reason: str


class Chronicle:
    def __init__(self, store_dir: Path) -> None:
        self.store = Path(store_dir)
        self.store.mkdir(parents=True, exist_ok=True)
        self.snapshots: List[Snapshot] = []

    def capture(self, path: Path, reason: str) -> Snapshot:
        path = Path(path)
        if path.exists():
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()[:16]
            stored = self.store / f"{digest}.snap"
            stored.write_bytes(data)
            snap = Snapshot(str(path), str(stored), True, time.time(), reason)
        else:
            snap = Snapshot(str(path), None, False, time.time(), reason)
        self.snapshots.append(snap)
        return snap

    def rollback_last(self) -> str:
        if not self.snapshots:
            return "nothing to roll back"
        snap = self.snapshots.pop()
        target = Path(snap.original_path)
        if snap.existed and snap.stored_path:
            shutil.copyfile(snap.stored_path, target)
            return f"restored {target}"
        if not snap.existed and target.exists():
            target.unlink()
            return f"removed {target} (did not exist before the action)"
        return f"no change needed for {target}"
