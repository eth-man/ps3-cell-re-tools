#!/usr/bin/env python3
"""Derive real function names from diagnostic strings.

Sony's error prints follow a fixed shape:

    brsl   <F>                         call the thing
    brz/brnz $3, ok                    check its result
    ...
    ila    $4, "In <enclosing>: "      which function we are in
    ila    $4, "<F> failed: "          which callee failed

So the `brsl` nearest *before* an "X failed:" print is X, and an "In Y:" print
names the function containing it. That yields the ORIGINAL names, which beats
porting invented symbols between builds.

  strname.py <elf> [--spec out.spec]
"""
import os, re, struct, sys, collections

elf = sys.argv[1]
d = open(elf, "rb").read()
phoff = struct.unpack(">I", d[0x1c:0x20])[0]
ent = struct.unpack(">H", d[0x2a:0x2c])[0]
nph = struct.unpack(">H", d[0x2c:0x2e])[0]
segs = []
for i in range(nph):
    o = phoff + i * ent
    t, off, va, pa, fsz, msz, fl, al = struct.unpack(">IIIIIIII", d[o:o + 32])
    if t == 1:
        segs.append((off, va, fsz))
if not segs:
    sys.exit("strname: no PT_LOAD segments")


def f2v(f):
    for off, va, fsz in segs:
        if off <= f < off + fsz:
            return va + (f - off)


def v2f(v):
    for off, va, fsz in segs:
        if va <= v < va + fsz:
            return off + (v - va)


strs = {}
for m in re.finditer(rb"[ -~]{6,}", d):
    v = f2v(m.start())
    if v is not None:
        strs[v] = m.group().decode("ascii", "replace")

# decode the text as instructions
ins = {}
for off, va, fsz in segs:
    for k in range(0, fsz - 3, 4):
        ins[va + k] = struct.unpack(">I", d[off + k:off + k + 4])[0]

ILA, BRSL = 0x21, 0x33
HELPER = 8          # a target called more than this often is a helper, not the callee

# The print/format helpers are called from every error block, so a naive
# "nearest preceding brsl" always finds them instead of the function that
# actually failed. Count call targets and treat the frequent ones as helpers.
_hist = collections.Counter()



def is_brsl(w):
    return (w >> 23) == 0x066 or (w >> 24) == BRSL


def brsl_target(va, w):
    imm = (w >> 7) & 0xFFFF
    if imm & 0x8000:
        imm -= 0x10000
    return (va + imm * 4) & 0x3FFFC


for _va, _w in ins.items():
    if (_w >> 24) == BRSL:
        _hist[brsl_target(_va, _w)] += 1

named = {}          # function va -> name
callee = {}         # function va -> name (from "X failed:")
enclosing = []      # (va, name) from "In X:"
for va in sorted(ins):
    w = ins[va]
    if (w >> 25) != ILA:
        continue
    tgt = (w >> 7) & 0x3FFFF
    s = strs.get(tgt)
    if not s:
        continue
    # Two forms of "this string is printed by X":
    #   "In X: ..."      (sc_iso, later builds)
    #   "X: ..."         (the ss_iso_dma_data / spulib_spu framework)
    m = (re.match(r"In ([A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)+)\s*:", s)
         or re.match(r"([A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)+)\s*:(?! *$)", s))
    if m:
        enclosing.append((va, m.group(1)))
        continue
    m = re.match(r"([A-Za-z_][\w:]*(?:::[\w]+)?)\s+failed", s)
    if m:
        # nearest preceding brsl that is NOT a print helper
        for back in range(va - 4, max(va - 4 * 120, 0), -4):
            w2 = ins.get(back)
            if w2 is None:
                continue
            if (w2 >> 24) == BRSL:
                t = brsl_target(back, w2)
                if _hist[t] > HELPER:          # print/format helper, keep walking
                    continue
                callee[t] = m.group(1)
                break

# an "In X:" print names the function that contains it: take the lowest brsl
# target at or below it that is a known function start is unreliable, so instead
# group consecutive "In X:" sites and report the range.
byname = collections.defaultdict(list)
for va, n in enclosing:
    byname[n].append(va)

# An "In X:" string is physically inside X, so walking back from the first such
# site to the function boundary gives X's entry directly. That is structurally
# stronger than the "<X> failed:" heuristic, which depends on guessing which
# preceding brsl was the failing call.
BI0 = 0x35000000
def entry_of(va):
    a = va
    while a > min(ins):
        prev = ins.get(a - 4)
        if prev is not None and (prev & 0xFFFFFF80) == BI0:   # bi $0 (return)
            b = a
            while ins.get(b) in (0x00200000, 0x40200000):     # lnop / nop padding
                b += 4
            return b
        a -= 4
    return None

enc_entry = {}
for n, vs in collections.defaultdict(list, {k: v for k, v in
        ((n, [va for va, nm in enclosing if nm == n]) for n in {nm for _, nm in enclosing})}).items():
    e = entry_of(min(vs))
    if e is not None:
        enc_entry[n] = e

print(f"{os.path.basename(elf)}")
# The "<X> failed:" heuristic guesses which preceding brsl was the failing call
# and is often wrong by one call site. Kept as a HINT and as a cross-check on the
# walk-back, never as the primary source.
print(f"\n  {len(callee)} hint(s) from '<name> failed:' prints (unreliable, cross-check only)")
print(f"\n  {len(enc_entry)} function(s) named from 'In <name>:' prints (entry resolved):")
for n, vs in sorted(byname.items(), key=lambda kv: min(kv[1])):
    e = enc_entry.get(n)
    print(f"    {'0x%05x'%e if e else '   ?   '}  {n}   ({len(vs)} site(s) "
          f"0x{min(vs):05x}..0x{max(vs):05x})")

# Built-in cross-check: the two derivations are independent. A name derived from
# "<X> failed:" gives X's ENTRY; a name derived from "In X:" gives addresses
# INSIDE X. Where both exist they must be consistent, and the entry must be the
# largest named entry at or below the "In X:" sites.
agree = disagree = 0
for n, vs in byname.items():
    ents = [va for va, nm in callee.items() if nm == n]
    if not ents:
        continue
    e2 = enc_entry.get(n)
    if e2 is not None and e2 in ents:
        agree += 1
    else:
        disagree += 1
        print(f"  !! {n}: 'failed:' says entry {[hex(x) for x in sorted(ents)]}, "
              f"'In X:' walk-back says {'0x%05x'%e2 if e2 else '?'} -- "
              f"trusting the walk-back")
# No two distinct names may resolve to the same entry -- that means the
# walk-back crossed a function boundary.
rev = collections.defaultdict(list)
for n, e in enc_entry.items():
    rev[e].append(n)
dupes = {e: ns for e, ns in rev.items() if len(ns) > 1}
for e, ns in sorted(dupes.items()):
    # The name whose first use sits closest to the entry owns it; the other is a
    # nested/adjacent function with no intervening `bi $0`, so its entry is
    # unknown rather than equal. Reporting them as equal would be a false name.
    owner = min(ns, key=lambda n: min(byname[n]))
    for n in ns:
        if n != owner:
            del enc_entry[n]
    print(f"  !! COLLISION 0x{e:05x} claimed by {ns}; assigned to {owner!r}, "
          f"{[n for n in ns if n != owner]} left UNRESOLVED (adjacent/inlined)")

# Entry order should follow the order of first use; a big inversion means a
# walk-back went too far back.
ordered = sorted(((min(byname[n]), enc_entry[n], n) for n in enc_entry), key=lambda t: t[0])
inv = sum(1 for a, b in zip(ordered, ordered[1:]) if b[1] < a[1])
print(f"\n  order check: {inv} inversion(s) of {max(1,len(ordered)-1)} "
      f"(entries should follow first-use order)")

if agree or disagree:
    print(f"\n  cross-check: {agree} name(s) confirmed by both derivations, "
          f"{disagree} inconsistent")
    if disagree:
        print("  (an inconsistency means one derivation is wrong -- do not trust either)")

if "--spec" in sys.argv:
    out = sys.argv[sys.argv.index("--spec") + 1]
    with open(out, "w") as f:
        f.write("# derived from Sony's own diagnostic strings by tools/strname.py\n")
        # ONLY the walk-back entries. Merging the "failed:" hints in would write
        # names at addresses the cross-check already showed to be wrong, and a
        # symbol file is exactly where a wrong name does the most damage.
        syms = {e: n for n, e in enc_entry.items()}
        for va in sorted(syms):
            f.write(f"{va:<6x} {syms[va].replace('::','__')}\n")
    print(f"\n  wrote {len(syms)} symbols to {out}")
