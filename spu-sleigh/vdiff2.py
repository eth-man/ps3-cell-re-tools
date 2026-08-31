#!/usr/bin/env python3
"""Version diff using GHIDRA's function boundaries, not a naive `bi` split.

An entry->`bi` splitter is unreliable on SPU: it merges functions that tail-call,
and swallows inter-function trap padding. Ghidra's analyser already produced
correct boundaries for every build in decomp/, so use those.

  vdiff2.py <old.c> <old.asm> <new.c> <new.asm>
"""
import re, sys, hashlib, difflib, collections

def entries(cfile):
    # NOTE: DumpFuncs.java emits '=================' and NameAndDecomp.java emits
    # '====='.  Matching only one silently yields 0 functions and a clean-looking
    # all-zero diff.  Tool bug #8 -- always run a control that must trip.
    ent = sorted(int(m, 16) for m in
                 re.findall(r'/\* =+ \S+ @ 0x([0-9a-f]+) =+ \*/', open(cfile).read()))
    if not ent:
        raise SystemExit('vdiff2: no function markers found in ' + cfile)
    return ent

def mnem(asm):
    d = {}
    for l in open(asm):
        m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)', l)
        if m: d[int(m.group(1), 16)] = m.group(2)
    return d

def bodies(cfile, asm):
    ent, ins = entries(cfile), mnem(asm)
    out = {}
    for i, a in enumerate(ent):
        end = ent[i+1] if i+1 < len(ent) else a + 4*4000
        b = [ins[x] for x in range(a, end, 4) if x in ins]
        if b: out[a] = b
    return out

A = bodies(sys.argv[1], sys.argv[2])
B = bodies(sys.argv[3], sys.argv[4])
h = lambda b: hashlib.sha1("\n".join(b).encode()).hexdigest()
hb = collections.Counter(h(b) for b in B.values())
same = moved = 0
leftA = []
for a, b in A.items():
    if hb[h(b)]:
        hb[h(b)] -= 1
        if a in B and h(B[a]) == h(b): same += 1
        else: moved += 1
    else: leftA.append((a, b))
matchedB = collections.Counter(h(b) for b in B.values())
usedA = collections.Counter(h(b) for b in A.values())
leftB = []
for a, b in B.items():
    k = h(b)
    if usedA[k]: usedA[k] -= 1
    else: leftB.append((a, b))
changed, added, removed = [], [], []
poolA = list(leftA)
for a, b in leftB:
    best, r = None, 0.0
    for oa, ob in poolA:
        s = difflib.SequenceMatcher(None, ob, b).ratio()
        if s > r: best, r = (oa, ob), s
    if best and r >= 0.60:
        changed.append((best[0], a, r, len(best[1]), len(b))); poolA.remove(best)
    else: added.append((a, len(b)))
allB = list(B.values())
for oa, ob in poolA:
    if max((difflib.SequenceMatcher(None, ob, nb).ratio() for nb in allB), default=0) < 0.60:
        removed.append((oa, len(ob)))
print(f"    same {same}  moved {moved}  changed {len(changed)}  "
      f"added {len(added)}  removed {len(removed)}")
if '-v' in sys.argv:
    for a, n in sorted(removed, key=lambda x: -x[1]):
        print(f"      REMOVED 0x{a:<7x} {n:>4} instrs")
    for a, n in sorted(added, key=lambda x: -x[1])[:10]:
        print(f"      ADDED   0x{a:<7x} {n:>4} instrs")
