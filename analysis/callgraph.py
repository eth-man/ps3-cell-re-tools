#!/usr/bin/env python3
"""SPU call graph from objdump output + Ghidra function boundaries.

  callgraph.py <decomp.c> <disasm.asm> paths <target-hex> [--from <hex>]
  callgraph.py <decomp.c> <disasm.asm> callers <hex>
  callgraph.py <decomp.c> <disasm.asm> tree <hex> [depth]
"""
import re, sys, collections

C, A = sys.argv[1], sys.argv[2]
ents = sorted(int(m, 16) for m in
              re.findall(r'/\* =+ \S+ @ 0x([0-9a-f]+) =+ \*/', open(C).read()))
def owner(a):
    lo, hi = 0, len(ents) - 1
    if a < ents[0]: return None
    while lo < hi:
        m = (lo + hi + 1) // 2
        if ents[m] <= a: lo = m
        else: hi = m - 1
    return ents[lo]

edges = collections.defaultdict(set)   # caller -> callees
rev = collections.defaultdict(set)
for l in open(A):
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(brsl|brasl)\s+\$\d+,\S+\s*#\s*([0-9a-f]+)', l)
    if not m: continue
    site, tgt = int(m.group(1), 16), int(m.group(3), 16)
    f = owner(site)
    if f is None: continue
    edges[f].add(tgt); rev[tgt].add(f)

cmd = sys.argv[3]
if cmd == 'callers':
    t = int(sys.argv[4], 16)
    print(' '.join('0x%x' % c for c in sorted(rev[t])) or '(none)')
elif cmd == 'tree':
    t = int(sys.argv[4], 16); depth = int(sys.argv[5]) if len(sys.argv) > 5 else 3
    seen = set()
    def go(f, d, pre):
        if d > depth: return
        print(pre + '0x%x' % f + (' *' if f in seen else ''))
        if f in seen: return
        seen.add(f)
        for c in sorted(edges[f]): go(c, d + 1, pre + '  ')
    go(t, 0, '')
elif cmd == 'paths':
    t = int(sys.argv[4], 16)
    # BFS upward to every root (function with no callers)
    dist = {t: []}
    q = collections.deque([t])
    roots = []
    while q:
        f = q.popleft()
        if not rev[f]:
            roots.append(f); continue
        for c in rev[f]:
            if c not in dist:
                dist[c] = [f] + dist[f]; q.append(c)
    for r in sorted(roots):
        print('ROOT 0x%x -> %s' % (r, ' -> '.join('0x%x' % x for x in dist.get(r, []))))
