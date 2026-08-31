#!/usr/bin/env python3
"""Port metldr's verified symbol names to another loader.

  xport.py <ref.asm> <target.asm> <ref.spec> <out.spec>

The loaders are built from the same source, so bodies match closely; the prologue
schedule does not, so entry-anchored matching fails. Three stages:

  1. window match   -- find a unique interior run of mnemonics, walk back to the
                       preceding `bi` for the entry
  2. propagate      -- where a located function's call SEQUENCE aligns 1:1 with
                       its reference twin, an unmapped target opposite a known
                       symbol must be that symbol; reject anything two callers
                       propose inconsistently
  3. verify         -- every mapped function must agree with its twin on BOTH
                       its complete call sequence AND its body (mnemonic
                       sequence, >=90% similar by difflib ratio, length
                       within 10%), or it is
                       dropped. The body check exists because 11 of metldr's 27
                       symbols are LEAVES: for those, call-sequence agreement is
                       empty-equals-empty and proves nothing on its own.

Only symbols surviving stage 3 are written out.
"""
import re, sys, difflib

def load(path):
    a, m, o = [], [], []
    for l in open(path):
        g = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*)', l)
        if g:
            a.append(int(g.group(1), 16)); m.append(g.group(2)); o.append(g.group(3))
    return a, m, o

class Bin:
    def __init__(self, path):
        self.a, self.m, self.o = load(path)
        self.idx = {addr: i for i, addr in enumerate(self.a)}
    def body(self, entry, cap=800):
        i = self.idx.get(entry)
        if i is None: return []
        out = []
        while i < len(self.a) and len(out) < cap:
            out.append(self.m[i])
            if self.m[i] == 'bi': break
            i += 1
        return out
    def calls(self, entry, cap=800):
        i = self.idx.get(entry)
        if i is None: return []
        out = []
        while i < len(self.a) and cap:
            if self.m[i] == 'brsl':
                t = re.search(r'0x([0-9a-f]+)', self.o[i])
                if t: out.append(int(t.group(1), 16))
            if self.m[i] == 'bi': break
            i += 1; cap -= 1
        return out
    def entry_of(self, i):
        while i > 0 and self.m[i-1] != 'bi': i -= 1
        return self.a[i]

def main():
    R, T = Bin(sys.argv[1]), Bin(sys.argv[2])
    spec = [l.split(None, 3) for l in open(sys.argv[3])
            if l.strip() and not l.startswith('#')]
    ref = {s[1]: int(s[0], 16) for s in spec}
    proto = {s[1]: (s[2], s[3].strip() if len(s) > 3 else '-') for s in spec}
    rev_ref = {v: k for k, v in ref.items()}
    mp = {}

    for name, addr in ref.items():                     # 1. window match
        b = R.body(addr)
        if len(b) < 12: continue
        for w in (24, 16, 12):
            if len(b) < w + 4: continue
            st = max(2, (len(b) - w) // 2)
            win = b[st:st+w]
            hits = [i for i in range(len(T.m) - w + 1) if T.m[i:i+w] == win]
            if len(hits) == 1:
                mp[name] = T.entry_of(hits[0] - st); break
    stage1 = len(mp)

    for _ in range(6):                                 # 2. propagate
        prop = {}
        for name, tgt in list(mp.items()):
            rc, tc = R.calls(ref[name]), T.calls(tgt)
            if len(rc) != len(tc): continue
            for rt, tt in zip(rc, tc):
                n = rev_ref.get(rt)
                if n and n not in mp: prop.setdefault(n, set()).add(tt)
        added = 0
        for n, c in prop.items():
            if len(c) == 1: mp[n] = c.pop(); added += 1
            else: print(f"  conflict, rejected: {n} -> {[hex(x) for x in c]}")
        if not added: break

    rev_mp = {v: k for k, v in mp.items()}             # 3. verify
    dropped = []
    for name, tgt in list(mp.items()):
        rc = [rev_ref.get(x) for x in R.calls(ref[name])]
        tc = [rev_mp.get(x) for x in T.calls(tgt)]
        rb, tb = R.body(ref[name]), T.body(tgt)
        # Body similarity, ALIGNMENT-AWARE. A positional compare is useless here:
        # the same function recompiled often gains or loses a leading `lnop`,
        # which shifts every index and scores 0% while being a 99% match.
        ratio = difflib.SequenceMatcher(None, rb, tb).ratio() if rb and tb else 0.0
        lenok = abs(len(rb) - len(tb)) <= max(2, 0.10 * len(rb))
        if rc != tc:
            dropped.append((name, 'call sequence')); del mp[name]
        elif not (lenok and ratio >= 0.90):
            dropped.append((name, f'body {ratio:.0%} len {len(rb)}/{len(tb)}'))
            del mp[name]
    print(f"window-matched {stage1}, after propagation {len(mp)+len(dropped)}, "
          f"verified {len(mp)}/{len(ref)}")
    if dropped:
        print("  dropped:", ", ".join(f"{n} ({why})" for n, why in dropped))
    print("  not located:", [n for n in ref if n not in mp and n not in dropped])

    with open(sys.argv[4], 'w') as f:
        f.write(f"# ported from {sys.argv[3]} by tools/spu-sleigh/xport.py\n"
                f"# verified: call sequence AND body (>=90% mnemonic match) agree\n"
                f"# with the reference. Leaf functions are covered by the body check.\n")
        for n in ref:
            if n in mp:
                r, p = proto[n]
                f.write(f"{mp[n]:<6x} {n:<19} {r:<5} {p}\n")
    print("wrote", sys.argv[4])

main()
