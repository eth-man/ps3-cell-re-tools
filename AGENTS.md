# AGENTS.md — working rules for this toolkit

This repository is a **measurement rig**. The tools here produced published
results, and those results are the contract: a change that alters one has
changed the record, not improved the tool.

## Before changing anything

```sh
python3 tests/replay_expectations.py --tool <tool>
```

This replays the published results the tool is responsible for. Run it before
your change and after it. If it was green and is now red, read the failure —
it names the finding and the exact measurement that moved.

Expectations come from the record repository
([ps3-ai-re](https://github.com/eth-man/ps3-ai-re)). If it is not reachable
from your checkout, the replay says "nothing to check" and passes. **That is
not a green light** — it means nothing was verified. Point it at the record:

```sh
PS3_EXPECTATIONS=../ps3-ai-re/expectations.json \
PS3_CORPUS=/path/to/decrypted/corpus \
python3 tests/replay_expectations.py
```

## The three outcomes, and what each means

| | |
| --- | --- |
| **PASS** | the published result survived your change |
| **FAIL** | your change altered a published measurement — or the measurement was wrong |
| **SKIP** | the artifact or the runner needed is not available here. Nothing was checked. |

A FAIL is not automatically your bug. If you believe the finding is wrong, say
so in the pull request and show why — a tool improvement that proves a
published result wrong is worth more than one that does not. That is how a
retraction starts.

## Artifacts

No firmware, no keys, and no decrypted Sony images are in this repository, and
none may be added. Expectations name what they need; supply it yourself via
`$PS3_CORPUS`. Tests skip cleanly without it.

## Adding a runner

`tests/replay_expectations.py` maps an expectation's `run` string to a
function via the `RUNNERS` registry. An unregistered runner **skips** — it does
not silently pass, and it does not fail a contributor's PR for something this
repository has not implemented yet. Register one when you wire up a tool entry
point, and the corresponding expectations start being checked.

## After a change lands

Tell the record. Findings pin `tool_commit:`, and a change that is not
reflected back leaves the record claiming a result was produced by a version
that no longer exists.
