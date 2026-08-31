#!/usr/bin/env python3
"""Do the SELF's unverified byte ranges reach Local Store?

sce_verify maps which file bytes a section digest covers.  Everything else in
the data region is unauthenticated: an attacker can edit it freely and isoldr
still LOADs (proven by single-bit flip).  The question that decides whether
that matters is not "is it checked" but "is it READ".  Unverified bytes that
never leave the EA buffer are inert padding; unverified bytes that land in
Local Store are an injection point.

So: fill each hole with a unique 8-byte tag, run the unforced harness, and
search the whole post-run Local Store (minus eid_root_key) for the tag.
"""
import os, re, struct, subprocess, sys, hashlib
PS3 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D   = os.path.join(PS3, 'glitchsim/isotest')
sys.path.insert(0, os.path.join(PS3, 'tools'))
from isoldr_matrix import keysets, appinfo, rvk_keyset
from sce_meta import decrypt
_erk = os.environ.get('PS3_EID_ROOT_KEY')

def holes(path):
    raw = open(path, 'rb').read()
    hl  = struct.unpack_from('>Q', raw, 0x10)[0]
    for fam, erk, riv in [(f, e, r) for f, e, r in _ks_all()]:
        try: blob, info = decrypt(path, erk, riv); break
        except Exception: continue
    cov = []
    for i in range(info['section_count']):
        off, size, t, idx, hashed, *_ = struct.unpack_from('>QQIIIIIIII', blob, 0x20 + i*0x30)
        if size and hashed == 2: cov.append((off, off + size))
    cov.sort(); cur = hl; out = []
    for a, b in cov:
        if a > cur: out.append((cur, a))
        cur = max(cur, b)
    if cur < len(raw): out.append((cur, len(raw)))
    return raw, out

def _ks_all():
    import re as _re
    txt = open(os.path.join(PS3, 'tools/scetool/data/keys')).read().replace('\r','')
    for blk in txt.split('[')[1:]:
        name, _, body = blk.partition(']')
        g = dict(_re.findall(r'^(\w+)=(\S+)$', body, _re.M))
        if 'erk' in g: yield name.strip(), bytes.fromhex(g['erk']), bytes.fromhex(g['riv'])

def run(mod_bytes, ks, tag=None):
    authid, vendor, stype, ver = appinfo(mod_bytes)
    krev = struct.unpack_from('>H', mod_bytes, 0x08)[0]
    erk = riv = None
    for v, rv, e, r in ks:
        if rv == krev and v <= ver: erk, riv = e, r; break
    open(f'{D}/ks_module.bin','wb').write(erk + riv)
    ea = bytearray(0x400000); ea[0x10000:0x10000+len(mod_bytes)] = mod_bytes
    open(f'{D}/ea.bin','wb').write(bytes(ea))
    args = bytearray(open(f'{D}/args.bin','rb').read())
    struct.pack_into('>10Q', args, 0, authid, authid, 0x10000,
                     (len(mod_bytes)+0x7f)&~0x7f, 0x200000, 0x30000,
                     0x300000, 0x1000, 0x310000, 0x1000)
    open(f'{D}/args.bin','wb').write(bytes(args))
    # dump ALL of Local Store except eid_root_key [0x0000,0x0040)
    env = dict(os.environ, ANERG_EA=f'{D}/ea.bin', ANERG_CH73=f'{D}/ch73.bin',
               ANERG_MBOX='1', ANERG_MAXI='2000000000', ANERG_TRACE='1',
               ANERG_LSPEEK='25fc0:40:3dfc0',
               ANERG_POKEF=f'28d1c:38870:{D}/ks_rvk.bin,29520:38900:{D}/ks_module.bin')
    cmd = [os.path.join(PS3,'tools/anergistic/anergistic'),
           '-L', f'{D}/args.bin@0x3e800', '-L', f'{D}/flag.bin@0x3e000',
           '-L', f'{D}/blk4.bin@0x3e400', '-L', f'{D}/blkc.bin@0x3ec00',
           '-L', f'{D}/hdr.bin@0x3f000']
    if _erk: cmd += ['-L', f'{_erk}@0x0']
    cmd.append(os.path.join(PS3,'extracted/loaders-493/TRUE-isoldr-493.elf'))
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600, cwd=PS3)
    calls = [l for l in r.stderr.splitlines() if l.startswith('[call]')]
    verdict = ('LOADED' if any('25fc0 -> 25970' in l for l in calls) else
               'refused' if any('25f14 -> 25970' in l for l in calls) else '?')
    hits = []
    m = re.search(r'\[LSPEEK\] pc=25fc0 (?:#\d+ i=\d+ )?LS\[00040\.\.3e000\] ([0-9a-f]+)', r.stderr)
    if m and tag:
        ls = bytes.fromhex(m.group(1)); i = 0
        while True:
            j = ls.find(tag, i)
            if j < 0: break
            hits.append(0x40 + j); i = j + 1
    return verdict, len(calls), hits, (bytes.fromhex(m.group(1)) if m else None)

if __name__ == '__main__':
    src = sys.argv[1] if len(sys.argv) > 1 else \
        'extracted/fw420/update_files/COS_pkg/CORE_OS/sv_iso_spu_module.self'
    ks = keysets()
    name, blob = rvk_keyset(os.path.join(PS3,'glitchsim/isotest/rvk.img'))
    open(os.path.join(PS3,'glitchsim/isotest/ks_rvk.bin'),'wb').write(blob)
    raw, gaps = holes(src)
    print("  %s   %d unverified holes\n" % (os.path.basename(src), len(gaps)))
    print("  %-24s %-8s %-8s %-7s %s" % ("hole","bytes","verdict","calls","tag found in LS"))
    v, c, _, ls = run(raw, ks)
    # POSITIVE CONTROL: a needle we know is in LS -- 16 bytes of the corpus's
    # own decrypted ELF at the load offset.  If this is not found, the dump or
    # the search is broken and every "NO" below is meaningless.
    import struct as _s
    sha = hashlib.sha256(raw).hexdigest()
    elf = open(os.path.join(PS3,'extracted/dec/%s.elf'%sha),'rb').read()
    ph  = _s.unpack_from('>I', elf, 0x1c)[0]
    off = _s.unpack_from('>8I', elf, ph)[1]
    needle = elf[off+0x40:off+0x50]
    ctrl = ls.find(needle) if ls else -1
    print("  %-24s %-8s %-8s %-7d %s" % ("(unmodified control)", "-", v, c,
          "POSITIVE CONTROL " + ("ok, plaintext at LS 0x%05x"%(0x40+ctrl) if ctrl>=0
                                 else "*** FAILED -- search path is broken ***")))
    for a, b in gaps:
        tag = b'\xde\xad' + struct.pack('>I', a) + b'\xbe\xef'
        m = bytearray(raw)
        for o in range(a, b): m[o] = tag[(o - a) % 8]
        v, c, hits, ls = run(bytes(m), ks, tag)
        where = ("NO -- never reaches LS" if ls else "(no LS dump)") if not hits else \
                "YES at " + ", ".join("LS 0x%05x" % h for h in hits[:6])
        print("  0x%06x..0x%06x %-6s %-8d %-8s %-7d %s" % (a, b, "", b - a, v, c, where))
