#!/usr/bin/env python3
"""Find the shared 'validate certification header' helper in each SPU verifier,
and report what value its callers demand for `sign_algorithm`.

The loaders share a codebase. isoldr's helper is at 0x35360 (notes/140):

    lqd     $6,0($4)        load the certification header
    rotqbyi $4,$6,8         bring +0x08 (sign_algorithm) into the preferred slot
    ceq     $3,$4,$5        compare against the CALLER's expected value (r5)
    brz     $3,<fail>       mismatch -> -1

So the accepted algorithm is not in the helper -- it is in each call site's `il $5,N`.
A caller passing 1 pins the file to ECDSA160 (fails closed). spp_verifier instead
compares inline against BOTH 1 and 3, and 3 is unkeyed (notes/384/385).

    python3 tools/signalg_helper.py disasm/*-493.asm
"""
import re, sys, os

LINE = re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} )+\s*(\S+)\s*(.*)$')

def parse(path):
    out = []
    for l in open(path, errors='replace'):
        m = LINE.match(l.rstrip('\n'))
        if m:
            out.append((int(m.group(1), 16), m.group(2), m.group(3).split('#')[0].strip()))
    return out

def find_helper(ins):
    """Locate `rotqbyi $x,$y,8` immediately followed (within 3) by a ceq/ceqi on $x,
    where $y came from a quadword load a few instructions earlier."""
    hits = []
    for i, (a, mn, ops) in enumerate(ins):
        if mn != 'rotqbyi': continue
        p = [x.strip() for x in ops.split(',')]
        if len(p) != 3 or p[2] != '8': continue
        src_loaded = any(ins[k][1] in ('lqd', 'lqx', 'lqr', 'lqa') and
                         ins[k][2].split(',')[0].strip() == p[1]
                         for k in range(max(0, i - 4), i))
        if not src_loaded: continue
        for j in range(i + 1, min(i + 4, len(ins))):
            a2, mn2, ops2 = ins[j]
            q = [x.strip() for x in ops2.split(',')]
            if mn2 in ('ceq', 'ceqi') and len(q) == 3 and q[1] == p[0]:
                hits.append((ins[i][0], mn2, q[2]))
                break
    return hits

def entry_of(ins, addr):
    idx = next(i for i, x in enumerate(ins) if x[0] == addr)
    for j in range(idx - 1, 0, -1):
        if ins[j][1] == 'bi' and ins[j][2].strip() == '$0':
            return ins[j + 1][0]
    return None

def callers_demand(ins, fn):
    """For each brsl to fn, what immediate went into $5 just before?"""
    out = []
    for k, (a, mn, ops) in enumerate(ins):
        if mn in ('brsl', 'brasl') and ops.endswith(hex(fn)):
            val = '?'
            for j in range(k - 1, max(0, k - 12), -1):
                q = [x.strip() for x in ins[j][2].split(',')]
                if ins[j][1] in ('il', 'ila', 'ilh') and q and q[0] == '$5':
                    val = q[1]; break
            out.append((a, val))
    return out

NAME = {'1':'ECDSA160','2':'HMACSHA1','3':'SHA1','5':'RSA2048','6':'HMACSHA256'}
if __name__ == '__main__':
    for p in sys.argv[1:]:
        ins = parse(p)
        hits = find_helper(ins)
        mod = os.path.basename(p).replace('.asm', '')
        if not hits:
            print("  %-30s  -" % mod); continue
        print("  %-30s" % mod)
        for addr, mn, val in hits:
            if mn == 'ceqi':
                print("        %05x  pinned inline to %s = %s" % (addr, val, NAME.get(val, '?')))
            else:
                fn = entry_of(ins, addr)
                cs = callers_demand(ins, fn) if fn else []
                dem = ", ".join("%s@%05x" % (v, a) for a, v in cs) or "no direct callers (indirect dispatch)"
                print("        %05x  caller-supplied (helper %s): %s"
                      % (addr, ('%05x' % fn) if fn else '?', dem))
