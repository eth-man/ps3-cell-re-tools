#!/usr/bin/env python3
"""Characterise the functions that vanished between two builds.

Listing 73 addresses is useless. For each removed function this reports its
size, who called it in the OLD build, and any distinctive immediates, so the set
can be clustered into subsystems rather than read as a flat list.
"""
import re, sys, hashlib, difflib, collections

def parse(path):
    ins = []
    for l in open(path):
        m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*)', l)
        if m: ins.append((int(m.group(1), 16), m.group(2), m.group(3)))
    return ins

PAD={'lnop','nop','stop','hbr','hbra','hbrr'}
def is_padding(body):
    m=[x[1] for x in body]
    return sum(1 for x in m if x in PAD or x=='br') >= 0.5*len(m)

def split(ins):
    out, cur, start = [], [], None
    for a, mn, ops in ins:
        if start is None: start = a
        cur.append((a, mn, ops))
        if mn == 'bi':
            if len(cur) > 3 and not is_padding(cur): out.append((start, cur))
            cur, start = [], None
    return out

A, B = parse(sys.argv[1]), parse(sys.argv[2])
FA, FB = split(A), split(B)
mn = lambda body: [m for _, m, _ in body]
h = lambda body: hashlib.sha1("\n".join(mn(body)).encode()).hexdigest()

hb = collections.Counter(h(b) for _, b in FB)
left = []
for a, b in FA:
    if hb[h(b)]: hb[h(b)] -= 1
    else: left.append((a, b))
# drop anything with a >=60% counterpart -- those are "changed", not removed
polB = [b for _, b in FB]
removed = []
for a, b in left:
    best = max((difflib.SequenceMatcher(None, mn(b), mn(o)).ratio() for o in polB),
               default=0.0)
    if best < 0.60: removed.append((a, b, best))

# callers within the OLD build
callers = collections.defaultdict(list)
for fa, body in FA:
    for _, m, ops in body:
        if m == 'brsl':
            t = re.search(r'0x([0-9a-f]+)', ops)
            if t: callers[int(t.group(1), 16)].append(fa)

print(f"{len(removed)} functions removed\n")
rset = {a for a, _, _ in removed}
# cluster: removed functions that call each other form a subsystem
adj = collections.defaultdict(set)
for a, body, _ in removed:
    for _, m, ops in body:
        if m == 'brsl':
            t = re.search(r'0x([0-9a-f]+)', ops)
            if t and int(t.group(1), 16) in rset:
                adj[a].add(int(t.group(1), 16)); adj[int(t.group(1), 16)].add(a)
seen, groups = set(), []
for a, _, _ in removed:
    if a in seen: continue
    stack, comp = [a], []
    while stack:
        x = stack.pop()
        if x in seen: continue
        seen.add(x); comp.append(x)
        stack.extend(adj[x] - seen)
    groups.append(sorted(comp))
groups.sort(key=len, reverse=True)
size = {a: len(b) for a, b, _ in removed}
ext = {a: sorted(set(callers[a]) - rset) for a, _, _ in removed}
print(f"clustered into {len(groups)} connected groups "
      f"(functions that call each other):\n")
for g in groups:
    tot = sum(size[a] for a in g)
    live = sorted({c for a in g for c in ext[a]})
    print(f"  group of {len(g):<3} ({tot} instrs)  entered from "
          f"{len(live)} surviving caller(s): {', '.join(hex(c) for c in live[:6])}"
          f"{' ...' if len(live) > 6 else ''}")
    for a in g[:6]:
        print(f"      0x{a:<7x} {size[a]:>4} instrs"
              f"{'   <- entry point' if ext[a] else ''}")
    if len(g) > 6: print(f"      ... and {len(g)-6} more")
