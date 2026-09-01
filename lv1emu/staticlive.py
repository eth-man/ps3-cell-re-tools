#!/usr/bin/env python3
"""Diff the STATIC lv1 image against the LIVE console for every address a run touches.

WHY THIS EXISTS (2026-09-01).  `lv1emu` demand-maps any unseeded address as a ZERO
page, so an offline chain silently reads zeros where hardware would machine-check or
find real data.  Two whole sessions were spent on conclusions that were emulator
artifacts:

  * the ACL `0x300dac` "denies with -16"      -- because [[0x358228]] is 0 offline
    and 0x609e00 live: the policy structure is RUNTIME-POPULATED, so static-only it
    finds nothing and denies.
  * `[0x385918]` (the SPU-manager radix root) is lv1 CODE statically and a real heap
    pointer live -- notes/192 had to forge it for the same reason.

Both are the SAME failure: a global that is null/garbage in the ELF and populated at
boot.  This tool finds them mechanically instead of one wrong conclusion at a time.

USAGE
    python3 tools/staticlive.py 0x358228 0x385918 ...      # explicit addresses
    python3 tools/staticlive.py --chain                    # run the 0x10043 producer
                                                           # and diff EVERYTHING it read
A row is only interesting when STATIC != LIVE.  Those are exactly the places the
offline model is fiction.  Pointer targets are followed one hop (`--depth`).
"""
NOTE_ON_DEPENDENCIES = """
This tool needs two console-side helpers that are intentionally NOT part of this repo,
because they encode one operator's setup rather than anything reusable:

  ps3mapi.read(addr, n) -> bytes   an lv1 memory reader.  Ours is a thin HTTP client for
                                   webMAN/PS3MAPI's getmem endpoint; it hard-codes a LAN
                                   address, so supply your own.
  lv1safe.classify_range(addr, n)  -> (ok, why).  A guard that refuses addresses outside
                                   the lv1 ELF's LOAD segments.  Reading an unmapped lv1
                                   address machine-checks the console, so DO NOT stub this
                                   out to "always true" -- write the real segment check.

Drop both next to this file and it runs.  The VALUE here is the method, not the client:
diff what the ELF says against what the running hypervisor actually holds.
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import lv1safe
except ImportError:
    lv1safe = None

def _emu():
    from lv1emu import Emu
    return Emu(verbose=False)

def static_read(e, a, n=8):
    try: return int.from_bytes(e.uc.mem_read(a, n), 'big')
    except Exception: return None

def live_read(a, n=8):
    if lv1safe is None:
        sys.exit("staticlive: missing lv1safe.py / ps3mapi.py -- see NOTE_ON_DEPENDENCIES")
    import ps3mapi
    ok, _ = lv1safe.classify_range(a, n)
    if not ok: return None
    time.sleep(0.05)                      # pace: fast unpaced getmem chokes webMAN
    try: return int.from_bytes(ps3mapi.read(a, n), 'big')
    except Exception: return None

def collect_reads(run):
    """Run `run(e)` and return every 8-byte-aligned lv1 address it READ.

    Uses a UC_HOOK_MEM_READ so we see real accesses, not just the demand set --
    demand only catches addresses that were never mapped, and the interesting ones
    (a global that IS in the ELF but holds 0 there) are already mapped."""
    from unicorn import UC_HOOK_MEM_READ
    e = _emu(); seen = set()
    def rd(uc, access, addr, size, value, ud):
        a = addr & ~7
        if 0x1000 <= a < 0x800000:        # lv1's own image/heap only, not our arena
            seen.add(a)
    e.uc.hook_add(UC_HOOK_MEM_READ, rd)
    run(e)
    return e, sorted(seen)

def report(pairs, depth=1):
    """pairs: iterable of addresses. Prints every STATIC != LIVE divergence.

    IMPORTANT: a pointer whose VALUE matches static-vs-live can still point at a
    structure that is empty offline and populated live -- that is exactly the ACL
    case ([0x358228] = 0x373d18 in BOTH, but [0x373d18] is 0 static / 0x609e00 live).
    The first version of this tool only followed pointers whose top level already
    differed, and so would have missed the finding it was written for.  Follow every
    plausible pointer regardless of whether its own value diverged."""
    e = _emu()
    pairs = list(pairs)
    rows, seen_hop = [], set()
    for a in pairs:
        s, l = static_read(e, a), live_read(a)
        if l is None or s is None: continue
        if s != l:
            rows.append((0, a, s, l))
        # follow the pointer even when s == l
        tgt = l if 0x1000 <= l < 0x800000 else None
        if depth and tgt and tgt not in seen_hop:
            seen_hop.add(tgt)
            s2, l2 = static_read(e, tgt), live_read(tgt)
            if s2 is not None and l2 is not None and s2 != l2:
                rows.append((1, tgt, s2, l2))
    print("%-14s %-18s %-18s" % ("ADDRESS", "STATIC", "LIVE"))
    for lvl, a, s, l in rows:
        pad = "   " * lvl
        tag = "<-- runtime-populated" if lvl == 0 else "<-- TARGET populated at boot"
        print("%s%#-*x %016x   %016x   %s" % (pad, 14 - 3*lvl, a, s, l, tag))
    print("\n%d divergences across %d addresses (%d direct, %d via pointer)"
          % (len(rows), len(pairs), sum(1 for r in rows if r[0]==0),
             sum(1 for r in rows if r[0]==1)))
    return rows

def chain_reads():
    import lv1sched as L, producer_forge as pf, producer_silicon as ps
    orig = L.stub
    def run(e_unused):
        pass
    # build + run inside the hooked emulator
    from unicorn import UC_HOOK_MEM_READ
    seen = set()
    def stub_skip(e, a):
        if a in (0x300dac,): return
        return orig(e, a)
    L.stub = stub_skip
    try:
        e, d, f = pf.build(0x1000, 0xE0, handle=11, verbose=False)
        ps.seed(e, 11)
        def rd(uc, access, addr, size, value, ud):
            a = addr & ~7
            if 0x1000 <= a < 0x800000: seen.add(a)
        e.uc.hook_add(UC_HOOK_MEM_READ, rd)
        e.run(0x2b80a8, {3: f['MSG'], 13: 0x38c100}, maxsteps=800000)
    finally:
        L.stub = orig
    return sorted(seen)

R2 = 0x35a038

def globals_of(funcs, asm='disasm/lv1-493.asm', span=0x400):
    """Every r2-relative global referenced inside the given functions.

    WHY: --chain under-reports badly.  lv1emu is catch-and-mock, so most global
    accesses happen inside Python shims and never reach Unicorn's read hook (a chain
    run collected exactly ONE address).  But this class of bug -- a global that is
    null in the ELF and populated at boot -- is always reached as `ld rX,-NNNN(r2)`,
    which is recoverable STATICALLY from the disassembly with full coverage."""
    import re
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(base, asm)
    want = sorted(funcs)
    out, cur, left = set(), None, 0
    pat = re.compile(r'^\s+([0-9a-f]{5,8}):\s.*?\b(?:ld|lwz|lwa)\s+r\d+,(-?\d+)\(r2\)')
    with open(path) as fh:
        for line in fh:
            m = re.match(r'^\s+([0-9a-f]{5,8}):', line)
            if not m: continue
            pc = int(m.group(1), 16)
            if pc in funcs: cur, left = pc, span
            if cur is None or left <= 0: continue
            left -= 4
            g = pat.match(line)
            if g: out.add(R2 + int(g.group(2)))
    return sorted(out)

if __name__ == '__main__':
    args = sys.argv[1:]
    if args and args[0] == '--globals':
        # the producer path: handler, ACL, policy compare, load chain, lookups
        FUNCS = {0x2b80a8, 0x300dac, 0x2e49e8, 0x31cb90, 0x31c1c8,
                 0x31a028, 0x2c9db4, 0x29d1d0, 0x2b4f80, 0x2b5714}
        g = globals_of(FUNCS)
        print("r2-relative globals referenced by the producer path: %d\n" % len(g))
        report(g)
    elif args and args[0] == '--chain':
        addrs = chain_reads()
        print("chain read %d distinct lv1 addresses; diffing against live ...\n" % len(addrs))
        report(addrs)
    elif args:
        report([int(a, 0) for a in args])
    else:
        print(__doc__)
