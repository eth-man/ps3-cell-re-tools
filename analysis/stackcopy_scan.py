#!/usr/bin/env python3
"""Find stack-destination copies with a non-constant length in SPU binaries.

The sv_iso pattern (notes/71): a DMA lands attacker bytes in Local Store, then a
memcpy moves `length` of them into a fixed-size stack frame whose saved link
register sits a short distance above the destination.

For every call to the module's memcpy, this reports:
  frame   the enclosing `ai $1,$1,-N` frame size
  dst     the `ai $rX,$1,M` stack offset the destination came from
  len     the last definition of $5 (const -> safe by construction)
  slack   frame + 16 - M, i.e. bytes from the destination to the saved LR

  stackcopy_scan.py <disasm.asm> [--all]
"""
import re, sys

A = sys.argv[1]
ins = {}
for l in open(A):
    m = re.match(r'\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*?)\s*$', l)
    if m:
        ins[int(m.group(1), 16)] = (m.group(2), m.group(3))

# memcpy: recognised by its prologue, independent of address
memcpys = {a for a, (mn, o) in ins.items()
           if mn == 'ori' and o == '$12,$5,0' and ins.get(a + 8, ('', ''))[1] == '$15,$3,0'}
if not memcpys:
    # Exit NON-ZERO: "no memcpy signature" means the scan could not run, which is
    # not the same as "no candidates" and must never be read as a clean result.
    print(f'{A}: ERROR no memcpy found (prologue signature absent) -- scan did not run',
          file=sys.stderr)
    sys.exit(2)

NOWRITE = {'stqd','stqx','stqa','stqr','br','bra','brz','brnz','brhz','brhnz','bi','biz',
           'binz','bihz','bihnz','bisl','bisled','iret','brsl','brasl','hbrr','hbra','hbrp',
           'nop','lnop','stop','stopd','wrch','sync','dsync'}
CONST = ('il','ila','ilh','ilhu','iohl','fsmbi')


def last_def(site, reg, win=60):
    for a in range(site - 4, max(site - 4 * win, 0) - 1, -4):
        if a not in ins: continue
        mn, o = ins[a]
        if mn in NOWRITE: continue
        m = re.match(r'\$(\d+)', o)
        if m and int(m.group(1)) == reg:
            return a, mn, o
    return None


def frame_of(site, win=400):
    """Nearest preceding stack adjustment.

    Two forms occur: `ai $1,$1,-N` for small frames and `il $rX,-N` + `a $1,$1,$rX`
    for large ones (me_iso's 2112-byte frame used the second and was read as 112
    when only the first was recognised)."""
    for a in range(site - 4, max(site - 4 * win, 0) - 1, -4):
        if a not in ins: continue
        mn, o = ins[a][0], ins[a][1].split('#')[0].strip()
        if mn == 'ai':
            m = re.match(r'\$1,\$1,(-\d+)$', o)
            if m: return -int(m.group(1))
        if mn == 'a':
            m = re.match(r'\$1,\$1,\$(\d+)$', o)
            if m:
                d = last_def(a, int(m.group(1)), 60)
                if d and d[1] in ('il', 'ila', 'ilh'):
                    mm = re.search(r',(-?\d+)', d[2].split('#')[0])
                    if mm and int(mm.group(1)) < 0: return -int(mm.group(1))
                return None
    return None


rows = []
for s in sorted(a for a, (mn, o) in ins.items()
                if mn in ('brsl', 'brasl')
                and (lambda t: t and int(t.group(1), 16) in memcpys)(re.search(r'#\s*([0-9a-f]+)', o))):
    dl = last_def(s, 5)
    if dl is None: continue
    lenkind = 'const' if dl[1] in CONST else 'COMPUTED'
    if lenkind == 'const' and '--all' not in sys.argv: continue
    # resolve the destination back to a stack offset, following register moves
    off, cur, at = None, 3, s
    for _ in range(4):
        d = last_def(at, cur, 200)
        if d is None: break
        a, mn, o = d
        o = o.split('#')[0].strip()          # objdump appends '# <hex>' comments
        mm = re.match(r'\$%d,\$1,(\d+)$' % cur, o)
        if mn == 'ai' and mm:                       # ai $rX,$1,M  -> stack slot
            off = int(mm.group(1)); break
        mm = re.match(r'\$%d,\$(\d+),0$' % cur, o)
        if mn in ('ori', 'shlqbyi') and mm:         # plain register move
            cur = int(mm.group(1)); at = a; continue
        break
    # A dynamic stack allocation (alloca) sized from the length is NOT a
    # fixed-frame overflow: the destination grows with the copy.  Detected by a
    # write to $1 between the prologue and the call.  Missing this produced
    # three false candidates in sc_iso (0x5a24 aside, 0x60bc and 0x6854).
    alloca = False
    for x in range(s - 4, max(s - 4 * 30, 0) - 1, -4):
        if x not in ins: continue
        mn2, o2 = ins[x]
        if mn2 in ('ori', 'a', 'sf', 'ai') and o2.startswith('$1,') and not o2.startswith('$1,$1,-'):
            alloca = True; break
    if alloca:
        continue
    fr = frame_of(s)
    slack = (fr + 16 - off) if (fr is not None and off is not None) else None
    rows.append((s, fr, off, slack, dl[1], dl[2], lenkind))

print(f'{A}: {len(rows)} stack-copy site(s)')
print('  %-9s %-7s %-7s %-7s %s' % ('site', 'frame', 'dst', 'slack', 'length'))
for s, fr, off, slack, mn, o, kind in rows:
    flag = ''
    if kind == 'COMPUTED' and slack is not None:
        flag = '   <== CANDIDATE (attacker length into a stack frame)'
    print('  0x%-7x %-7s %-7s %-7s %-8s %-22s%s'
          % (s, fr if fr is not None else '?', off if off is not None else '?',
             slack if slack is not None else '?', mn, o, flag))
