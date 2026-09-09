# harnesses/

The measurement harnesses behind published findings. Each one names the finding
it produced and the expectations that replay it.

| harness | produced | expectations |
| --- | --- | --- |
| `svtest.sh` | F-0071 — the sv_iso stack overflow | `E-0071-*` |
| `verifygate.sh` | F-0129 — appldr's verify-skip is `ctx+0xE9` | `E-0129-*` |
| `lv1procs.py` | F-0110 — lv1's seven embedded programs | `E-0110-*` |
| `isofuzz.py` | F-0436 — the hijack is 4.20-only | `E-0436-*` |
| `signalg_helper.py` | F-0388 — spp_verifier is the only one that fails open | — |

## What you supply

```sh
export PS3_CORPUS=/path/to/decrypted/modules
export ANERGISTIC=../anergistic/anergistic     # or build it: make -C anergistic
```

No firmware, no keys and no decrypted Sony images are in this repository, and
none may be added. The harnesses read what you point them at.

## Version is always pinned

Every harness selects its module **by version and refuses to substitute**.

That rule is here because an earlier draft of `verifygate.sh` used a loose
`find` and quietly picked `corpus/356/appldr.elf` — a 3.56 module — for a 4.93
measurement. It produced a confident wrong answer that looked like a broken
finding. A harness that silently swaps the artifact is worse than one that does
not run, so they now print which file they used and exit rather than guess.

## Payload fixtures are generated, not shipped

`svtest.sh` and `verifygate.sh` build their input pages at run time into a temp
file. Nothing is committed, and the generation is visible in the script, which
is the point: the input is part of the measurement.

## Running them through the record

```sh
python3 ../tests/replay_expectations.py --expectations ../../ps3-ai-re/expectations.json
```

Against a full corpus that replays as 7 passed, 0 failed — the 224/228 overflow
boundary, both markers, lv1's seven programs by name, and the `0xE6` inert /
`0xE9` gate pair.
