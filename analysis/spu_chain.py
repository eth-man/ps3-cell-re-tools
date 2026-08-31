#!/usr/bin/env python3
"""Walk the upward call chain to a target in an SPU disassembly.

Function boundaries are taken as "the first non-padding instruction after a
`bi $0`", which is what the SPU ABI actually emits; deriving them from brsl
targets alone mis-assigns call sites in functions that are only reached
indirectly.

  spu_chain.py <disasm.asm> <target-hex> [maxdepth]
"""
import re, sys, bisect, collections

A, TGT = sys.argv[1], int(sys.argv[2], 16)
MAXD = int(sys.argv[3]) if len(sys.argv) > 3 else 10
ins = {}
for l in open(A):
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*?)\s*$', l)
    if m:
        ins[int(m.group(1), 16)] = (m.group(2), m.group(3))
addrs = sorted(ins)

starts = [addrs[0]]
for i, a in enumerate(addrs[:-1]):
    if ins[a][0] == 'bi' and ins[a][1].split('#')[0].strip() == '$0':
        b = addrs[i + 1]
        while b in ins and ins[b][0] in ('lnop', 'nop'):     # inter-function padding
            j = addrs.index(b) + 1
            if j >= len(addrs): break
            b = addrs[j]
        starts.append(b)
starts = sorted(set(starts))


def owner(a):
    i = bisect.bisect_right(starts, a) - 1
    return starts[i] if i >= 0 else None


rev = collections.defaultdict(set)
kind = {}
STARTS = set(starts)
for a, (mn, o) in ins.items():
    t = re.search(r'#\s*([0-9a-f]+)', o)
    if not t:
        continue
    tgt = int(t.group(1), 16)
    f = owner(a)
    if f is None or tgt == f:
        continue
    # `brsl` is a call. A plain `br` whose target is a FUNCTION ENTRY is a TAIL
    # CALL and is just as much an edge -- counting only brsl reported lv1's
    # isolate-load path as having no callers at all (tool bug #15), and there
    # are 14 such edges in sv_iso 4.20 alone.
    if mn in ('brsl', 'brasl'):
        rev[tgt].add(f); kind[(f, tgt)] = 'call'
    elif mn in ('br', 'bra') and tgt in STARTS:
        rev[tgt].add(f); kind[(f, tgt)] = 'tail'


print(f'{len(starts)} functions; upward chain to 0x{TGT:x}')
seen, frontier = {TGT}, [TGT]
for d in range(MAXD):
    print(f'  depth {d}: ' + ' '.join(f'0x{x:x}' for x in sorted(frontier)))
    nxt = []
    for f in frontier:
        for c in rev.get(f, ()):
            if c not in seen:
                seen.add(c); nxt.append(c)
                print(f'            0x{c:x} --{kind.get((c,f),"?")}--> 0x{f:x}')
    if not nxt:
        roots = [f for f in frontier if not rev.get(f)]
        print('  roots (no direct caller -> entry or indirect dispatch): '
              + ' '.join(f'0x{x:x}' for x in sorted(roots)))
        break
    frontier = nxt
