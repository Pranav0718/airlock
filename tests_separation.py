"""
Makes the separation claim checkable instead of just asserted in prose.

The agent module must not pull in the executor or the broker. If someone later
wires execution into the reasoning side, this test fails, which is the whole
point: the boundary is enforced, not trusted.

Run:  python tests_separation.py
"""

import ast
import sys
from pathlib import Path

FORBIDDEN = {"airlock.tools", "airlock.broker", "subprocess", "socket"}


def imports_of(path: Path):
    tree = ast.parse(path.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                found.add(n.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module)
    return found


def main() -> int:
    agent_dir = Path(__file__).parent / "agent"
    bad = []
    for py in agent_dir.glob("*.py"):
        used = imports_of(py)
        leaks = used & FORBIDDEN
        if leaks:
            bad.append((py.name, leaks))

    if bad:
        for name, leaks in bad:
            print(f"FAIL  {name} imports {leaks}")
        print("\nThe reasoning side must not hold execution capability.")
        return 1

    print("PASS  the agent side imports nothing that can touch the world.")
    print("      reasoning proposes, the broker disposes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
