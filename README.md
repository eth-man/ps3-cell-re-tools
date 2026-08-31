# PS3 Cell / SPU reverse-engineering toolkit

The instruments behind **[Execution Is Not Extraction →](https://eth-man.github.io/execution-is-not-extraction/)**
— the tools built to reverse and *emulate* the PlayStation 3's Cell/SPU secure-boot chain
(`metldr → isoldr → isolated modules`) entirely offline, so a hypothesis could be settled on a
workstation instead of on a console that reboots into a red screen of death on every wrong guess.

None of this is a jailbreak or a key dump. It is the **measurement rig**: emulate the SPU, decompile
it soundly, run the `lv1` hypervisor offline, and diff every result against a second implementation so
a decode bug shows up as a divergence instead of a silent wrong answer.

---

## The instruments

### `anergistic/` — extended SPU emulator &nbsp;·&nbsp; GPLv2
A fork of fail0verflow's [anergistic](https://github.com/psfree/anergistic) SPU emulator, extended for
isolated-module work:
- an **MFC DMA model** (single + list transfers, tag groups) so an isolated module's own I/O actually runs;
- **taint tracking** — follow attacker-controlled bytes into saved registers / the link register;
- **channel capture** — the outbound mailbox (ch28) and the SPU debug-char console are recorded, not dropped;
- metadata injection past the SRVK barrier, to drive the loader handshakes.

Upstream is GPLv2 and this fork keeps it; original copyright fail0verflow `<master@fail0verflow.com>`.

### `spu-sleigh/` — a *sound* SPU decompiler
Generates a 128-bit lane-correct Ghidra **SLEIGH** model of the SPU ISA (`make_spec.py`) plus a
**differential harness** (`vdiff*.py`, `xport.py`, `xmatch.py`) that diffs every decompiled function
against the anergistic emulator. The two implementations gate each other. Built on top of the
[GhidraSPU](https://github.com/aerosoul94/GhidraSPU) processor module as its base.

### `lv1emu/` — offline `lv1` (hypervisor) PPC64 executor
Runs `lv1`'s isolate-load handler chain under Unicorn with catch-and-mock on a 970FX (Cell PPE lineage)
core — no console, no reboot loop. This is what replaced *push → launch → RSOD → repeat*.

### `isoldr-harness/` — isolation-loader harness
Boots a real `isoldr` under the extended anergistic, clears its loader-channel **version handshake**
(the gate that stops most attempts), and drives the isolated-module argument staging — all offline.

### `audit/` — corpus vulnerability-class auditor
`spu_frame_audit.py` sweeps a corpus of decrypted SPU modules for the `sv_iso` bug class: a
variable-length copy into a stack frame smaller than the copy can be.

### `analysis/` — static-analysis odds and ends
`lv1` ELF/segment parsing, SPU CFG + callgraph, SS symbol mapping, SCE metadata readout, stack-copy
scanning, string naming.

---

## What is deliberately **not** here

Tooling only. This repo contains **no console keys, no decrypted Sony firmware, and no live console
exploit payload** — those stay private. The companion writeup is about a *defense that holds*, not a
recipe. Bring your own, legally obtained, firmware to point these tools at.

## Credits

**fail0verflow** (anergistic, and the 2010 metldr / ECDSA work), **aerosoul94** (GhidraSPU),
**Mathieulh**, **geohot**, and the wider PS3 scene.

## License

GPLv2, inherited from anergistic. See [`LICENSE`](LICENSE). Third-party components remain under their
own terms.
