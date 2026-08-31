#!/usr/bin/env python3
"""Run ONE module through the unforced isoldr harness in its own staging dir.

Exists so the slow modules can run in parallel: tools/isoldr_matrix.py stages
into a single shared glitchsim/isotest, so concurrent runs would clobber each
other's ea.bin / args.bin / ks_module.bin.

usage: isoldr_one.py <module.self> <outdir> [seconds]
"""
import os, re, struct, subprocess, sys, shutil, time

PS3 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(PS3, 'glitchsim/isotest')
sys.path.insert(0, os.path.join(PS3, 'tools'))
from sce_meta import decrypt
from isoldr_matrix import keysets, appinfo, rvk_keyset

mod_path, out, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 7200
os.makedirs(out, exist_ok=True)
for f in ('flag.bin', 'blk4.bin', 'blkc.bin', 'hdr.bin', 'ch73.bin', 'args.bin'):
    shutil.copy(os.path.join(SRC, f), os.path.join(out, f))

_, blob = rvk_keyset(os.path.join(SRC, 'rvk.img'))
open(f'{out}/ks_rvk.bin', 'wb').write(blob)

mod = open(mod_path, 'rb').read()
authid, vendor, stype, ver = appinfo(mod)
krev = struct.unpack_from('>H', mod, 0x08)[0]
erk = riv = None
for v, rv, e, r in keysets():
    if rv == krev and v <= ver:
        erk, riv = e, r; break
if erk is None:
    for v, rv, e, r in keysets():
        if rv == krev:
            erk, riv = e, r; break
decrypt(mod_path, erk, riv)                      # pad check: right keyset
open(f'{out}/ks_module.bin', 'wb').write(erk + riv)

ea = bytearray(0x400000); ea[0x10000:0x10000 + len(mod)] = mod
open(f'{out}/ea.bin', 'wb').write(bytes(ea))
args = bytearray(open(f'{out}/args.bin', 'rb').read())
struct.pack_into('>10Q', args, 0, authid, authid, 0x10000,
                 (len(mod) + 0x7f) & ~0x7f, 0x200000, 0x30000,
                 0x300000, 0x1000, 0x310000, 0x1000)
open(f'{out}/args.bin', 'wb').write(bytes(args))

env = dict(os.environ, ANERG_EA=f'{out}/ea.bin', ANERG_CH73=f'{out}/ch73.bin',
           ANERG_MBOX='1', ANERG_MAXI='20000000000', ANERG_TRACE='1',
           ANERG_POKEF=f'28d1c:38870:{out}/ks_rvk.bin,29520:38900:{out}/ks_module.bin')
cmd = [os.path.join(PS3, 'tools/anergistic/anergistic'),
       '-L', f'{out}/args.bin@0x3e800', '-L', f'{out}/flag.bin@0x3e000',
       '-L', f'{out}/blk4.bin@0x3e400', '-L', f'{out}/blkc.bin@0x3ec00',
       '-L', f'{out}/hdr.bin@0x3f000']
k = os.environ.get('PS3_EID_ROOT_KEY')
if k: cmd += ['-L', f'{k}@0x0']
cmd.append(os.path.join(PS3, 'extracted/loaders-493/TRUE-isoldr-493.elf'))

t0 = time.time()
with open(f'{out}/run.out', 'w') as so, open(f'{out}/run.err', 'w') as se:
    try:
        subprocess.run(cmd, stdout=so, stderr=se, env=env, timeout=secs, cwd=PS3)
        why = 'exited'
    except subprocess.TimeoutExpired:
        why = 'TIMEOUT after %ds' % secs
print("%-28s %s in %.0fs" % (os.path.basename(mod_path), why, time.time() - t0))
