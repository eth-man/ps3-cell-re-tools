#!/usr/bin/env python3
"""Run one isoldr against several sv_iso modules and report where each stops.

This is the question the whole offline harness exists to answer: does isoldr
4.93 load an OLDER isolated module?  Everything it needs is derived from the
module itself -- expected auth_id from app_info, the isoldr keyset from the
module's declared version -- so adding a module is a one-line change.

UNFORCED (notes/141).  No stubs, no metadata injections, no pokes:
  * the loader is the UNPATCHED TRUE-isoldr-493.elf
  * isoldr computes the ECDSA/SHA-1 verdicts itself and they PASS
  * ctx+0x5C comes from lv1's real 0x3E400 block, MAC-verified with the
    console's own eid_root_key (PS3_EID_ROOT_KEY)

The only substitution is 96 bytes of PUBLIC firmware constant.  isoldr normally
receives its keysets over the ch64/ch73 isolation loader channel, which the
emulator does not implement; we plant the published equivalents at the two
destinations isoldr would have filled:
      RVK keyset     LS 0x38870 (32B erk) + 0x38890 (16B riv)   at pc 0x28d1c
      module keyset  LS 0x38900 (32B erk) + 0x38920 (16B riv)   at pc 0x29520
Note prog.srvk needs the [rvk] family, NOT [isoldr].
"""
import os, re, struct, subprocess, sys

PS3 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
D   = os.path.join(PS3, 'glitchsim/isotest')

def keysets(family='isoldr'):
    """(version, revision, erk, riv) for every entry of `family`, newest first."""
    txt = open(os.path.join(PS3, 'tools/scetool/data/keys')).read().replace('\r', '')
    out = []
    for blk in txt.split('[')[1:]:
        name, _, body = blk.partition(']')
        if not name.strip().startswith(family):
            continue
        g = dict(re.findall(r'^(\w+)=(\S+)$', body, re.M))
        if 'erk' in g:
            # the file carries BOTH revision 0x0001 and 0x0100 entries for the
            # same version.  The module's SCE header names which revision it was
            # signed under; ignoring that picks the wrong erk for >= 4.53 and
            # the metadata_info pads come out non-zero.
            out.append((int(g['version'], 16), int(g['revision'], 16),
                        bytes.fromhex(g['erk']), bytes.fromhex(g['riv'])))
    return sorted(out, reverse=True)

def appinfo(mod):
    ai = struct.unpack_from('>Q', mod, 0x28)[0]        # self_hdr.app_info_offset
    authid, vendor, stype, ver = struct.unpack_from('>QIIQ', mod, ai)
    return authid, vendor, stype, ver

# PS3_EID_ROOT_KEY=<path> makes ctx+0x5C GENUINE: isoldr verifies lv1's real
# 0x3E400 authority block itself and writes 0x84. Without it we fall back to
# poking ctx+0x5C=0x81, which is a legal class but not the true one (notes/140).
# The key is per-console identity: pass it, never commit it, never publish it.
_erk = os.environ.get('PS3_EID_ROOT_KEY')
if _erk and not os.path.exists(_erk):
    raise SystemExit("PS3_EID_ROOT_KEY=%s does not exist" % _erk)


def rvk_keyset(rvk_path):
    """Find the keyset that actually decrypts the staged revocation list."""
    sys.path.insert(0, os.path.join(PS3, 'tools'))
    from sce_meta import decrypt
    txt = open(os.path.join(PS3, 'tools/scetool/data/keys')).read().replace('\r', '')
    for blk in txt.split('[')[1:]:
        name, _, body = blk.partition(']')
        g = dict(re.findall(r'^(\w+)=(\S+)$', body, re.M))
        if 'erk' not in g or not name.strip().startswith('rvk'):
            continue
        try:
            decrypt(rvk_path, bytes.fromhex(g['erk']), bytes.fromhex(g['riv']))
        except Exception:
            continue
        return name.strip(), bytes.fromhex(g['erk']) + bytes.fromhex(g['riv'])
    raise SystemExit("no [rvk] keyset decrypts %s" % rvk_path)


def run_one(path, ks):
    sys.path.insert(0, os.path.join(PS3, 'tools'))
    from sce_meta import decrypt
    mod = open(path, 'rb').read()
    authid, vendor, stype, ver = appinfo(mod)
    krev = struct.unpack_from('>H', mod, 0x08)[0]       # sce_hdr.key_revision
    erk = riv = None
    for v, rv, e, r in ks:
        if rv == krev and v <= ver:
            erk, riv, kv = e, r, v
            break
    if erk is None:
        for v, rv, e, r in ks:
            if rv == krev:
                erk, riv, kv = e, r, v
                break
    # sanity: this keyset must actually decrypt the module (pad check)
    blob, info = decrypt(path, erk, riv)
    open(f'{D}/ks_module.bin', 'wb').write(erk + riv)

    ea = bytearray(0x400000)
    ea[0x10000:0x10000 + len(mod)] = mod
    open(f'{D}/ea.bin', 'wb').write(bytes(ea))

    args = bytearray(open(f'{D}/args.bin', 'rb').read())
    struct.pack_into('>10Q', args, 0, authid, authid,
                     0x10000, (len(mod) + 0x7f) & ~0x7f, 0x200000, 0x30000,
                     0x300000, 0x1000, 0x310000, 0x1000)
    open(f'{D}/args.bin', 'wb').write(bytes(args))

    env = dict(os.environ,
               ANERG_EA=f'{D}/ea.bin', ANERG_CH73=f'{D}/ch73.bin', ANERG_MBOX='1',
               ANERG_MAXI='2000000000', ANERG_TRACE='1',
               ANERG_LSPEEK='25fc0:880:17000',
               # the two published keysets, standing in for the ch73 stream
               ANERG_POKEF=f'28d1c:38870:{D}/ks_rvk.bin,'
                           f'29520:38900:{D}/ks_module.bin')
    cmd = [os.path.join(PS3, 'tools/anergistic/anergistic'),
           '-L', f'{D}/args.bin@0x3e800', '-L', f'{D}/flag.bin@0x3e000',
           '-L', f'{D}/blk4.bin@0x3e400', '-L', f'{D}/blkc.bin@0x3ec00',
           '-L', f'{D}/hdr.bin@0x3f000']
    if _erk:
        cmd += ['-L', f'{_erk}@0x0']
    cmd.append(os.path.join(PS3, 'extracted/loaders-493/TRUE-isoldr-493.elf'))
    r = subprocess.run(cmd, capture_output=True, text=True, env=env,
                       timeout=420, cwd=PS3)
    calls = [l for l in r.stderr.splitlines() if l.startswith('[call]')]
    ecdsa = sum(1 for l in calls if re.search(r'-> 3[0-3][0-9a-f]{3}', l))
    dmas  = [l for l in r.stdout.splitlines() if l.startswith('[DMA')]
    stop  = next((l.split(':')[-1].strip() for l in reversed(r.stdout.splitlines())
                  if 'stop instruction reached' in l), '?')
    # isoldr's own exit sites: 25f14 = error, 25fc0 = success
    # ground truth: the corpus's own decrypted ELF for this exact SELF
    import hashlib, sqlite3, re as _re
    sha = hashlib.sha256(mod).hexdigest()
    plain = os.path.join(PS3, 'extracted/dec/%s.elf' % sha)
    pct = None
    m = _re.search(r'\[LSPEEK\] pc=25fc0 (?:#\d+ i=\d+ )?LS\[00880\.\.17880\] ([0-9a-f]+)', r.stderr)
    if m and os.path.exists(plain):
        ls = bytes.fromhex(m.group(1))
        elf = open(plain, 'rb').read()
        ph = struct.unpack_from('>I', elf, 0x1c)[0]
        _, off, va, _, fsz, _, _, _ = struct.unpack_from('>8I', elf, ph)
        n = min(fsz, len(ls))
        exp = elf[off:off + n]
        pct = 100.0 * sum(a == b for a, b in zip(exp, ls[:n])) / max(n, 1)
    verdict = ('LOADED'  if any('25fc0 -> 25970' in l for l in calls) else
               'refused' if any('25f14 -> 25970' in l for l in calls) else '?')
    return dict(authid=authid, vendor=vendor, stype=stype, ver=ver,
                keyver=kv, krev=krev,
                calls=len(calls), dmas=len(dmas), stop=stop, verdict=verdict, pct=pct, ecdsa=ecdsa,
                info=info)

if __name__ == '__main__':
    ks = keysets()
    name, blob = rvk_keyset(os.path.join(PS3, 'glitchsim/isotest/rvk.img'))
    open(os.path.join(PS3, 'glitchsim/isotest/ks_rvk.bin'), 'wb').write(blob)
    print("loader = isoldr 4.93, UNPATCHED (TRUE-isoldr-493.elf)")
    print("  revocation keyset [%s];  eid_root_key %s" %
          (name, "staged" if _erk else "NOT SET -- 0x3E400 MAC will fail"))
    print("  no stubs, no metadata injections, no pokes\n")
    print(f"  {'module':<34} {'ver':>9} {'auth_id':>18} {'keyset':>9} "
          f"{'calls':>7} {'DMA':>4} {'ecdsa':>7} {'stop':>6}  {'plaintext':>9}  verdict")
    for p in sys.argv[1:]:
        try:
            r = run_one(p, ks)
        except Exception as e:
            print(f"  {os.path.basename(p):<34} ERROR: {e}")
            continue
        print(f"  {os.path.basename(p):<34} {r['ver']>>32:>9x} "
              f"{r['authid']:018x} {r['keyver']>>32:>9x} "
              f"{r['calls']:>7} {r['dmas']:>4} {r['ecdsa']:>7} {r['stop']:>6}  "
              f"{('%8.3f%%' % r['pct']) if r['pct'] is not None else '       --':>9}  {r['verdict']}")
