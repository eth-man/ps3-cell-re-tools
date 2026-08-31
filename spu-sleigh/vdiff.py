#!/usr/bin/env python3
"""Function-level diff of the same loader across firmware versions.

Splits each image into functions (entry -> `bi`), fingerprints each by its
mnemonic sequence, and classifies across a version pair:

    same     identical mnemonic sequence
    moved    identical body, different address
    changed  >=60% similar -- same function, edited
    added    no counterpart in the older build
    removed  no counterpart in the newer build

Named symbols are called out, since a change inside a known function is the
interesting kind.
"""
import re, sys, hashlib, difflib, os

PAD = {'lnop', 'nop', 'stop', 'hbr', 'hbra', 'hbrr'}

def is_padding(body):
    """Trap/alignment filler between functions: runs of lnop / br-to-self / nop.
    Parsed as a 'function' by any naive entry->bi splitter, and it changes size
    between builds, which fakes large add/remove deltas."""
    n = sum(1 for m in body if m in PAD or m == 'br')
    return n >= 0.5 * len(body)

def funcs(path):
    ins = []
    for l in open(path):
        m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)', l)
        if m: ins.append((int(m.group(1), 16), m.group(2)))
    out, cur, start = [], [], None
    for a, mn in ins:
        if start is None: start = a
        cur.append(mn)
        if mn == 'bi':
            if len(cur) > 3 and not is_padding(cur): out.append((start, cur))
            cur, start = [], None
    return out

def names(spec):
    d = {}
    if spec and os.path.exists(spec):
        for l in open(spec):
            if l.strip() and not l.startswith('#'):
                f = l.split(); d[int(f[0], 16)] = f[1]
    return d

def main():
    a_asm, b_asm = sys.argv[1], sys.argv[2]
    a_spec = sys.argv[3] if len(sys.argv) > 3 else None
    b_spec = sys.argv[4] if len(sys.argv) > 4 else None
    A, B = funcs(a_asm), funcs(b_asm)
    an, bn = names(a_spec), names(b_spec)
    h = lambda b: hashlib.sha1("\n".join(b).encode()).hexdigest()
    ah = {}
    for addr, body in A: ah.setdefault(h(body), []).append((addr, body))
    used_b, same, moved = set(), 0, []
    unmatched_b = []
    ahs = {k: list(v) for k, v in ah.items()}
    for addr, body in B:
        k = h(body)
        if k in ahs and ahs[k]:
            oaddr, _ = ahs[k].pop()
            if oaddr == addr: same += 1
            else: moved.append((oaddr, addr, body))
            used_b.add(addr)
        else:
            unmatched_b.append((addr, body))
    leftover_a = [(a, b) for lst in ahs.values() for a, b in lst]
    # a leftover A function is only "removed" if nothing in ALL of B resembles
    # it -- not merely nothing in the unconsumed remainder
    allB = [b for _, b in B]
    changed, added = [], []
    for addr, body in unmatched_b:
        best, bestr = None, 0.0
        for oaddr, obody in leftover_a:
            r = difflib.SequenceMatcher(None, obody, body).quick_ratio()
            if r > bestr:
                r2 = difflib.SequenceMatcher(None, obody, body).ratio()
                if r2 > bestr: best, bestr = (oaddr, obody), r2
        if best and bestr >= 0.60:
            changed.append((best[0], addr, bestr, len(best[1]), len(body)))
            leftover_a.remove(best)
        else:
            added.append((addr, len(body)))
    still = []
    for oa, ob in leftover_a:
        if max((difflib.SequenceMatcher(None, ob, nb).ratio() for nb in allB),
               default=0.0) < 0.60:
            still.append((oa, ob))
    leftover_a = still
    print(f"  {os.path.basename(a_asm)} -> {os.path.basename(b_asm)}")
    print(f"    same {same}   moved {len(moved)}   changed {len(changed)}   "
          f"added {len(added)}   removed {len(leftover_a)}")
    for oa, na, r, l1, l2 in sorted(changed, key=lambda x: -abs(x[4]-x[3]))[:12]:
        nm = an.get(oa) or bn.get(na) or ''
        print(f"      changed 0x{oa:<7x}-> 0x{na:<7x} {r:.0%} similar  "
              f"{l1}->{l2} instrs  {nm}")
    for na, l in sorted(added, key=lambda x: -x[1])[:8]:
        print(f"      ADDED   0x{na:<7x} {l} instrs  {bn.get(na,'')}")
    for oa, b in sorted(leftover_a, key=lambda x: -len(x[1]))[:8]:
        print(f"      REMOVED 0x{oa:<7x} {len(b)} instrs  {an.get(oa,'')}")

main()
