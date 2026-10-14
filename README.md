# Airlock

A small, runnable broker that keeps an AI agent's reasoning away from its execution.

**Reasoning proposes. The broker disposes.**

The agent can only ever propose a tool call. A separate trusted broker decides what actually runs. Even a fully compromised agent cannot touch the filesystem, run a command, or make a request on its own, because it holds no execution capability at all.

This is a study implementation I built after reading two 2026 papers on agent security. It is a teaching reference, not a production system, and the limitations section below is honest about where it stops short.

## Why

I read two papers that attack the same problem from opposite ends:

- **Parallax** (Fokou, 2026) argues that prompt level guardrails are useless once the model is compromised, because the guardrail lives inside the thing that got compromised. The fix is architectural: separate the reasoner from the executor and put an independent validator between them.
- **SMCP** (Hou et al., 2026) argues that the Model Context Protocol has no real identity, trust, or audit layer, and proposes adding one at the protocol level.

Parallax asks *is this action safe to run?* SMCP asks *who is asking, and are they allowed?* Neither is complete alone. Airlock combines both into one broker and then closes a gap that both papers leave open.

## What it does

Every proposed action runs through tiers, cheapest and most predictable first, and only a permissive verdict reaches the executor.

```
   agent (sandboxed, no tools)          broker (trusted)
   +------------------------+           +-----------------------------+
   |  Planner.propose(goal) | --------> |  Tier 0  deterministic policy|
   |  builds Action objects |  gRPC in  |  flow    information flow     |
   |  imports NOTHING that  |  a real   |  prov    file provenance      |
   |  can act on the world  |  deploy   |  Tier 1  heuristic scan       |
   +------------------------+           |  Tier 2  human or model eval  |
                                        +--------------+----------------+
                                                       | permit only
                                                       v
                                        +-----------------------------+
                                        | Executor  (the only code    |
                                        | that touches the world)     |
                                        | Chronicle snapshots first   |
                                        | Audit log chains every call |
                                        +-----------------------------+
```

### Mapped to the papers

| Mechanism | Source | File |
| --- | --- | --- |
| Reasoning cannot execute | Parallax P1 | `agent/planner.py`, `tests_separation.py` |
| Tiered validation, fail closed | Parallax P2 | `broker.py`, `policy.py`, `heuristics.py` |
| Information flow control | Parallax P3 | `ifc.py` |
| Reversible execution | Parallax P4 | `chronicle.py` |
| Validator self protection | Parallax | `policy.py` (self protect rules) |
| Identity and delegation chain | SMCP | `identity.py` |
| Security context, broker owned | SMCP | `identity.py`, `broker.py` |
| Permit / deny / permit with obligations | SMCP | `action.py` |
| Hash chained signed audit | both | `audit.py` |

### What I added

Both papers admit the same hole. Parallax says plainly that it checks the command that runs a script but never reads the script itself, so an agent can write a malicious file (a permitted write) and then execute it (a permitted command), and the logic inside is never inspected.

`provenance.py` tracks which files the agent authored this session. If the agent later tries to execute one of them, the broker refuses, because it never got to validate what is inside. A human can still approve it, but it does not pass silently. It is a small change to the trust posture based on the one honest signal the broker actually has: where the file came from.

## Run it

No dependencies. Standard library only. Python 3.10 or newer.

```
python tests_separation.py     # proves the agent side holds no execution capability
python demo.py                 # narrated walk through every mechanism
python -m harness.run_eval     # the assume compromise scoreboard
```

On Windows use `python`, not `python3`.

## Results

The harness uses the **assume compromise** method from Parallax: it does not try to jailbreak a model. It assumes the agent is already fully compromised and injects the malicious action straight into the broker, then checks the boundary holds.

```
attacks blocked      18/18  (100.0%)
false positives      0/5    (0.0%)
tier that resolved   T0:6, T1:8, T2:4
audit chain          intact
```

Read that honestly: **this is my own curated test set, not an independent benchmark.** A number against cases I wrote proves the mechanisms fire as designed. It does not prove coverage against attacks I did not think of. Real evaluation would run against something like AgentDojo or InjecAgent, which is listed under next steps.

## Limitations

I would rather state these than have someone find them.

- **Single process, not real OS isolation.** The agent and broker run in one Python process for readability. The separation is enforced by the agent module importing nothing that can act (checked by `tests_separation.py`), not by a process boundary. A faithful deployment puts the executor in its own process reachable only over a narrow channel, the way Parallax describes.
- **Heuristics, not a learned classifier.** Tier 1 is pattern matching plus a small decoder for base64 and hex. Parallax also runs a fine tuned model here. That is where a model would slot in.
- **The test set is mine.** See above.
- **Workspace sandbox is a demo guard, not a security boundary.** All actions are confined to one directory so the demo cannot touch your machine. That confinement is convenience, not a claim.

## Next steps

- Run against a public benchmark instead of my own cases.
- Put the executor in a real separate process with a typed channel.
- Swap the Tier 1 heuristics for a classifier trained on agent actions rather than prompt injection text.
- Expand provenance to full taint tracking on agent authored content.

## Credit

Ideas from *Parallax: Why AI Agents That Think Must Never Act* (Joel Fokou, 2026) and *SMCP: Secure Model Context Protocol* (Hou, Wang, Zhang, Xue, Zhao, Fu, Wang, 2026). This repo is my own implementation and synthesis of their ideas, with the provenance mechanism as the one piece that is mine.

MIT licensed.
