#!/usr/bin/env python3
"""Recover Sony's function names in PPC64 images (lv1, lv2_kernel, vsh).

The SPU version (tools/strname.py) walks back to a `bi $0` to find a function
entry. PPC64 ELFv1 is better than that: the **.opd** table lists every function
descriptor as (entry, toc, env), so function starts are exact, not inferred.

String references are TOC-relative:
    addi rX, r2, off      -> address is TOC + off
    ld   rX, off(r2)      -> address is *(TOC + off)
and the TOC base is the second word of every OPD descriptor -- identical across
the whole module, which makes it self-verifying (6873 agreeing entries in lv1).

  strname_ppc.py <elf> [--spec out.spec] [--all]
"""
import collections, os, re, struct, sys

elf = sys.argv[1]
d = open(elf, "rb").read()
if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 2:
    sys.exit("strname_ppc: not a big-endian ELF64")
phoff = struct.unpack(">Q", d[0x20:0x28])[0]
ent = struct.unpack(">H", d[0x36:0x38])[0]
nph = struct.unpack(">H", d[0x38:0x3a])[0]
segs = []
for i in range(nph):
    o = phoff + i * ent
    t, fl = struct.unpack(">II", d[o:o + 8])
    off, va, pa, fsz, msz, al = struct.unpack(">QQQQQQ", d[o + 8:o + 56])
    if t == 1:
        segs.append((off, va, fsz, fl))
if not segs:
    sys.exit("strname_ppc: no PT_LOAD segments")
EX = [(o, v, f) for o, v, f, fl in segs if fl & 1]


def v2f(v):
    for off, va, fsz, fl in segs:
        if va <= v < va + fsz:
            return off + (v - va)


def f2v(f):
    for off, va, fsz, fl in segs:
        if off <= f < off + fsz:
            return va + (f - off)


def inexec(a):
    return any(v <= a < v + f for _, v, f in EX)


# --- TOC base: the second word of every OPD descriptor, identical module-wide
toc = collections.Counter()
opd = {}
for off, va, fsz, fl in segs:
    for k in range(0, fsz - 23, 8):
        f0, t0, e0 = struct.unpack(">QQQ", d[off + k:off + k + 24])
        if inexec(f0) and 0 < t0 < 0x1000000 and e0 == 0:
            toc[t0] += 1
if not toc:
    sys.exit("strname_ppc: no OPD descriptors found")
TOC, agree = toc.most_common(1)[0]
total = sum(toc.values())
print(f"{os.path.basename(elf)}")
print(f"  TOC base 0x{TOC:x}  ({agree}/{total} OPD descriptors agree)")

funcs = set()
for off, va, fsz, fl in segs:
    for k in range(0, fsz - 23, 8):
        f0, t0, e0 = struct.unpack(">QQQ", d[off + k:off + k + 24])
        if t0 == TOC and e0 == 0 and inexec(f0):
            funcs.add(f0)
F = sorted(funcs)
print(f"  {len(F)} function entries from .opd")


def owner(a):
    import bisect
    i = bisect.bisect_right(F, a) - 1
    return F[i] if i >= 0 else None


strs = {}
for m in re.finditer(rb"[ -~]{6,}", d):
    v = f2v(m.start())
    if v is not None:
        strs[v] = m.group().decode("ascii", "replace")

# Sony's trace prints take several shapes, all of which START with the emitting
# function's name:
#     "update_manager::swap_bank(%d, 0x%llx)\n"
#     "update_manager::read failure\n"
#     "!!! virtual_trm_manager::restart_objs [setup_header] : array_t::setup"
#     "In sc_iso_module::get_syscon_state: "
# Requiring a trailing ':' (the sc_iso shape) missed all the lv1 ones. Take the
# FIRST class::method in the string -- a later one is a callee, not the emitter.
NAME = re.compile(r"^(?:!+\s*)?(?:In\s+)?([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\s*(?:[(:\[ ]|$)")
hits = collections.defaultdict(list)
nref = 0
for off, va, fsz, fl in segs:
    if not (fl & 1):
        continue
    pend = {}
    for k in range(0, fsz - 3, 4):
        w = struct.unpack(">I", d[off + k:off + k + 4])[0]
        op, ra = w >> 26, (w >> 16) & 0x1F
        imm = w & 0xFFFF
        if imm & 0x8000:
            imm -= 0x10000
        tgt = None
        rt = (w >> 21) & 0x1F
        if op == 15 and ra == 2:                 # addis rX, r2, ha  -> high half
            pend[rt] = TOC + (imm << 16)
            continue
        if op == 14 and ra == 2:                 # addi rX, r2, off  (small offset)
            tgt = TOC + imm
        elif op == 14 and ra == rt and rt in pend:
            tgt = pend.pop(rt) + imm             # ...the addi completing an addis
        elif op == 58 and ra == 2:               # ld rX, off(r2)
            f = v2f(TOC + (imm & ~3))
            if f is not None:
                tgt = struct.unpack(">Q", d[f:f + 8])[0]
        elif op == 58 and ra == rt and rt in pend:
            f = v2f(pend.pop(rt) + (imm & ~3))
            if f is not None:
                tgt = struct.unpack(">Q", d[f:f + 8])[0]
        if tgt is None:
            continue
        s = strs.get(tgt)
        if not s:
            continue
        nref += 1
        m = NAME.match(s)
        if m:
            fn = owner(va + k)
            if fn is not None:
                hits[m.group(1)].append(fn)

print(f"  {nref} TOC string reference(s); {len(hits)} name(s) matched a class::method form")
named = {}
for n, fs in hits.items():
    c = collections.Counter(fs)
    best, cnt = c.most_common(1)[0]
    named[best] = (n, cnt, len(fs))

rev = collections.defaultdict(list)
for a, (n, _, _) in named.items():
    rev[n].append(a)
coll = {n: a for n, a in rev.items() if len(a) > 1}
for n, a in sorted(coll.items()):
    print(f"  !! {n} claimed at {[hex(x) for x in sorted(a)]}")

print(f"\n  {len(named)} function(s) named:")
for a in sorted(named):
    n, cnt, tot = named[a]
    flag = "" if cnt == tot else f"   ({cnt}/{tot} refs agree)"
    print(f"    0x{a:06x}  {n}{flag}")

if "--spec" in sys.argv:
    out = sys.argv[sys.argv.index("--spec") + 1]
    with open(out, "w") as f:
        f.write(f"# {os.path.basename(elf)} -- from Sony's diagnostic strings, "
                f"TOC 0x{TOC:x}, .opd function entries\n")
        for a in sorted(named):
            f.write(f"{a:<8x} {named[a][0].replace('::','__')}\n")
    print(f"\n  wrote {len(named)} symbols to {out}")
