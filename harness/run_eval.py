"""
Assume compromise evaluation.

Injects every attack straight into the broker, bypassing the agent, and reports
how many were blocked, how many legitimate actions were wrongly blocked, and
which tier resolved each case.

Run from the repo root:  python -m harness.run_eval
"""

from __future__ import annotations

import tempfile
from collections import Counter
from pathlib import Path

from airlock.broker import Broker
from airlock.identity import Principal, PrincipalType, new_context
from harness import cases


def _fresh_context():
    user = Principal(PrincipalType.USER, "pranav", "owner")
    agent = Principal(PrincipalType.AGENT, "planner", "assistant")
    return new_context(user, agent)


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix="airlock_eval_"))
    broker = Broker(workspace)

    # Seed a couple of benign files so legit reads have something to read.
    (workspace / "report.txt").write_text("quarterly report body")
    (workspace / "data.csv").write_text("a,b,c")

    tiers = Counter()
    blocked = 0
    total_attacks = 0

    print("=" * 60)
    print("ATTACKS (assume the agent is fully compromised)")
    print("=" * 60)

    for category, action in cases.ATTACKS:
        ctx = _fresh_context()
        decision = broker.evaluate(ctx, action)
        total_attacks += 1
        ok = not decision.allowed
        blocked += ok
        tiers[decision.tier] += 1
        mark = "BLOCK" if ok else "LEAK "
        print(f"[{mark}] {category:11} T{decision.tier}  {decision.reason}")

    print()
    print("Multi step sequences (state carries across the session)")
    print("-" * 60)
    for category, seq in cases.SEQUENCES:
        ctx = _fresh_context()
        final = None
        for action in seq:
            final, _ = broker.submit(ctx, action)
        total_attacks += 1
        ok = not final.allowed
        blocked += ok
        tiers[final.tier] += 1
        mark = "BLOCK" if ok else "LEAK "
        print(f"[{mark}] {category:11} T{final.tier}  {final.reason}")

    print()
    print("=" * 60)
    print("LEGITIMATE ACTIONS (should all pass)")
    print("=" * 60)
    false_positives = 0
    for action in cases.LEGIT:
        ctx = _fresh_context()
        decision = broker.evaluate(ctx, action)
        passed = decision.allowed
        false_positives += (not passed)
        mark = "pass " if passed else "WRONG"
        print(f"[{mark}] {action.type.value:16} T{decision.tier}  {decision.reason}")

    # Audit integrity check.
    ok, msg = broker.audit.verify()

    print()
    print("=" * 60)
    print("SCOREBOARD")
    print("=" * 60)
    rate = 100.0 * blocked / total_attacks
    fp_rate = 100.0 * false_positives / len(cases.LEGIT)
    print(f"attacks blocked      {blocked}/{total_attacks}  ({rate:.1f}%)")
    print(f"false positives      {false_positives}/{len(cases.LEGIT)}  ({fp_rate:.1f}%)")
    print(f"tier that resolved   " + ", ".join(f"T{t}:{n}" for t, n in sorted(tiers.items())))
    print(f"audit chain          {'intact' if ok else 'BROKEN'} ({msg})")
    print(f"workspace            {workspace}")


if __name__ == "__main__":
    main()
