#!/usr/bin/env python3
"""isoldr harness — run a real isoldr under anergistic against a real container.

WHAT WORKS (2026-08-27, notes/96):
  * boots the real isoldr and clears its ctor/init path
  * passes isoldr's LOADER-CHANNEL VERSION HANDSHAKE, which is the gate that
    stopped every previous attempt (notes/63 hit the same stop 0x30 in appldr)
  * reaches the isolated-module argument staging that copies 80 bytes to LS
    0x3E800 -- the notes/81 arg-delivery path

WHAT DOES NOT WORK YET:
  * the load-request context is not populated, so the run ends at stop 0x17,
    an alignment/nonzero check on context+0x10 at isoldr 0x264b8.

THE PROTOCOL (reversed from isoldr-493):

  0x34df8  ch_read(skip=$3, dst=$4, count=$5)
             wrch ch64, 0x10000 ; discard `skip` words ; read `count` words -> dst
  0x34f10  read_version()  -- ch_read(skip=0, count=2), assembles (w0<<32)|w1
  0x34f80  cmp64(expected) -- returns 0 ONLY on exact equality
  0x272d0  request handler -- expected comes from `lqr $3,0x360c0`, a constant
           in isoldr's OWN DATA.  Mismatch -> return 48 -> stop 0x30.

  That constant is the loader's own build version, one occurrence per image:

      isoldr 3.55  0x0003005500000000      isoldr 4.20  0x0004002000000000
      isoldr 3.56  0x0003005600000000      isoldr 4.93  0x0004009300000000
      isoldr 3.60  0x0003006000000000

  So the handshake word pair is (version_hi32, version_lo32) and it must match
  the loader's own version exactly.  NOTE this constrains which LOADER may run,
  not which MODULE may be loaded -- it is checked before any module DMA.

usage:
  isoldr_harness.py <isoldr.elf> <module.self> [--version 0x0004009300000000]
                    [--maxi N] [--ls FILE@ADDR ...] [--verbose]
"""
import sys, os, struct, subprocess, argparse, re

# isoldr 4.93 stop codes seen so far (notes/138).  0x16 is returned by FOUR
# different functions, so the code alone does not localise the failure --
# that is what --trace is for.
STOP_MEANING = {
    '00000016': 'SRVK metadata rejected (0x35360). Without the metadata '
                'injection this is where every run stops -- see notes/139',
    '0000000f': 'past SRVK validation; fails later, in the ECDSA/curve stage',
    '00000017': 'load-request context +0x10: the two doublewords must be '
                '16-byte aligned and nonzero (isoldr 0x264b8)',
    '00000030': 'loader-channel version handshake rejected',
    '00000025': 'expected auth_id / vendor:self_type at arg block +0x00 is not '
                'a well-formed authority id (top nibble must be 1) or does not '
                'match the module app_info (isoldr 0x271bc/0x271d4)',
}
# functions that can return 22 (0x16), from `il $rX,22` sites in isoldr 4.93
ERR_SITES = (0x26d20, 0x28738, 0x28c68, 0x28ecc, 0x28778)

SRC_EA, DST_EA, RVK_EA, EA_SIZE = 0x10000, 0x200000, 0x300000, 0x400000

# one occurrence per image; keyed by the isoldr build
KNOWN_VERSIONS = {
    '355': 0x0003005500000000, '356': 0x0003005600000000,
    '360': 0x0003006000000000, '420': 0x0004002000000000,
    '493': 0x0004009300000000,
}

def infer_version(path):
    """Recover the loader's own version constant straight out of the image:
    the unique 8-byte 0x000M00VV00000000 value that is not an LS address."""
    d = open(path, 'rb').read()
    cand = {}
    for i in range(0, len(d) - 8, 4):
        v, = struct.unpack('>Q', d[i:i+8])
        if v & 0xFFFFFFFF: continue
        # version encoding is bytes  00 0M 00 VV 00 00 00 00 -- byte 2 is ZERO.
        # LS addresses (0x000257ff.., 0x00010560..) always have byte 2 nonzero,
        # which is what separates them cleanly.
        if (v >> 48) in range(1, 10) and ((v >> 40) & 0xff) == 0 and ((v >> 32) & 0xff):
            cand[v] = cand.get(v, 0) + 1
    return sorted(cand)[-1] if cand else None

def run(isoldr, module, version, maxi, extra_ls, verbose=False, d='glitchsim/isotest',
        rvk=None, trace=False, inject_meta=True, authid=None, vendorty=None):
    os.makedirs(d, exist_ok=True)
    mod = open(module, 'rb').read()
    ea = bytearray(EA_SIZE)
    assert SRC_EA + len(mod) < EA_SIZE
    ea[SRC_EA:SRC_EA+len(mod)] = mod
    # isoldr validates the revocation list BEFORE the module: 0x35250 demands
    # magic 'SCE\0', version 2, header_type 2 (SRVK).  Absent/zero -> stop 0x16.
    rvk_len = 0
    if rvk:
        rb = open(rvk, 'rb').read()
        ea[RVK_EA:RVK_EA+len(rb)] = rb
        rvk_len = (len(rb) + 0x7f) & ~0x7f
    open(f'{d}/ea.bin', 'wb').write(bytes(ea))
    words = [version >> 32, version & 0xFFFFFFFF] + [0] * 254
    open(f'{d}/ch73.bin', 'wb').write(b''.join(struct.pack('>I', w) for w in words))
    # 80-byte iso-module arg block, staged at LS 0x3E800 (notes/81).  isoldr copies
    # it into its context at 0x38b30 and validates +0x10: two 64-bit values, both
    # nonzero and 16-byte aligned, else stop 0x17.
    # the module's own app_info -- SELF header at 0x20, appinfo_offset at +0x10
    ai = struct.unpack_from('>Q', mod, 0x20 + 0x08)[0]   # self_hdr.app_info_offset
    m_authid, m_vendor, m_type = struct.unpack_from('>QII', mod, ai)
    authid   = m_authid if authid is None else authid
    vendorty = ((m_vendor << 32) | m_type) if vendorty is None else vendorty
    args = bytearray(0x50)
    # CORRECTED 2026-08-28.  notes/79 called the first two doublewords
    # "type, flags".  They are not.  Measured: isoldr copies args[0x00:0x10]
    # verbatim into its context at 0x38b30, and 0x271bc tests
    #     (u64 at ctx+0x00) >> 60 == 1   and   the same on the module's own
    # app_info pair fetched by 0x28108 from SELF file offset appinfo_offset.
    # They are the EXPECTED program_authority_id and vendor_id:self_type --
    # i.e. lv1 declares which module it believes it is loading, and isoldr
    # checks the module agrees.  With "5, 0" there the run stops at 0x25
    # (isoldr 0x272ac, `il $4,37`), because 5 >> 60 != 1.
    #   sv_iso 4.20: authid=0x1070000024000001 vendor=0x07000001 type=5
    struct.pack_into('>10Q', args, 0, authid, vendorty,
                     SRC_EA, (len(mod) + 0x7f) & ~0x7f, DST_EA, 0x30000,
                     RVK_EA, rvk_len or 0x1000, RVK_EA + 0x10000, 0x1000)
    open(f'{d}/args.bin', 'wb').write(bytes(args))
    # notes/81: lv1 DMAs FOUR blocks into LS -- 0x3E800 plus 0x3E400, 0x3EC00
    # and 0x3F000 -- then releases with 0x3E000 = 0x000000FF.  The harness used
    # to stage only 0x3E800, leaving three regions and the flag at zero; a
    # Local Store dump showed 1KB of zeros at each.  isoldr's 0x28f08 copies
    # 4096 bytes out of 0x3F000 and parses them, so that block is very likely
    # the module's SELF header.
    open(f'{d}/flag.bin', 'wb').write(struct.pack('>4I', 0xFF, 0, 0, 0))
    # LS 0x3F000 holds the REVOCATION LIST, not the module.  isoldr's 0x28f08
    # copies 4096 bytes out of it and 0x35250 then demands magic SCE\0,
    # version 2 and header_type == 2 -- and type 2 IS a revocation list (a SELF
    # is type 1).  Staging the module header here fails that check; staging an
    # SRVK gets 19 calls further, into the signature verification.
    rvkblob = b''
    if rvk:
        rvkblob = open(rvk, 'rb').read()
    open(f'{d}/hdr.bin',  'wb').write(rvkblob[:0x1000].ljust(0x1000, b'\0'))
    open(f'{d}/blk4.bin', 'wb').write(bytes(0x400))
    open(f'{d}/blkc.bin', 'wb').write(bytes(0x400))
    cmd = ['tools/anergistic/anergistic', '-m', str(maxi),
           '-L', f'{d}/args.bin@0x3e800',
           '-L', f'{d}/flag.bin@0x3e000',
           '-L', f'{d}/blk4.bin@0x3e400',
           '-L', f'{d}/blkc.bin@0x3ec00',
           '-L', f'{d}/hdr.bin@0x3f000']
    for spec in extra_ls or []:
        cmd += ['-L', spec]
    cmd.append(isoldr)
    env = dict(os.environ, ANERG_EA=f'{d}/ea.bin', ANERG_CH73=f'{d}/ch73.bin', ANERG_MBOX='1')
    if trace: env['ANERG_TRACE'] = '1'
    # Inject the DECRYPTED SRVK metadata (header + section headers + the 14 file
    # keys) at LS 0x39310 just before isoldr validates it.  anergistic cannot
    # reproduce isoldr's in-SPU metadata decryption -- it produces garbage, so
    # 0x35360 rejected with -1.  The plaintext comes from scetool -i / -d, which
    # CAN decrypt it with the keysets in ~/.ps3/keys.  With it injected 0x35360
    # returns 0 and the run advances 386 -> 428 calls, stop 0x16 -> 0x0F.
    mf = os.path.join(d, 'meta_full.bin')
    if inject_meta and os.path.exists(mf):
        env['ANERG_POKEF'] = '28de8:39310:%s' % mf
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    out = r.stdout
    err = r.stderr or ''
    stop = next((l.split(':')[-1].strip() for l in reversed(out.splitlines())
                 if 'stop instruction reached' in l), None)
    dmas = [l for l in out.splitlines() if l.startswith('[DMA')]
    ch73 = [l for l in out.splitlines() if 'CH73_DATA' in l]
    calls = [l for l in err.splitlines() if l.startswith('[call]')]
    if verbose: print(out[-4000:])
    return stop, ch73, dmas, calls

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('isoldr'); ap.add_argument('module')
    ap.add_argument('--version', default=None)
    ap.add_argument('--maxi', type=int, default=4000000)
    ap.add_argument('--ls', action='append')
    ap.add_argument('--rvk', default=None, help='revocation list (SRVK) to stage at RVK_EA')
    ap.add_argument('--verbose', action='store_true')
    ap.add_argument('--no-inject-meta', action='store_true',
                    help='do NOT inject the decrypted SRVK metadata (see notes/139)')
    ap.add_argument('--authid', default=None,
                    help='expected program_authority_id (default: the module\'s own)')
    ap.add_argument('--vendorty', default=None,
                    help='expected vendor_id:self_type as one u64 (default: the module\'s own)')
    ap.add_argument('--trace', action='store_true',
                    help='capture the emulator call trace and attribute the stop code')
    a = ap.parse_args()
    ver = int(a.version, 0) if a.version else infer_version(a.isoldr)
    if ver is None:
        sys.exit("could not infer the loader version constant; pass --version")
    stop, ch73, dmas, calls = run(a.isoldr, a.module, ver, a.maxi, a.ls, a.verbose,
                                  rvk=a.rvk, trace=a.trace,
                                  inject_meta=not a.no_inject_meta,
                                  authid=int(a.authid, 0) if a.authid else None,
                                  vendorty=int(a.vendorty, 0) if a.vendorty else None)
    print(f"loader={os.path.basename(a.isoldr)} module={os.path.basename(a.module)}")
    print(f"  version handshake = 0x{ver:016x}   ch73 reads={len(ch73)}")
    print(f"  stop = {stop}   DMAs = {len(dmas)}")
    print(f"  {'PASSED the version gate' if stop != '00000030' else 'REJECTED at the version gate (stop 0x30)'}")
    for l in dmas[:8]: print("   ", l)
    if stop and stop in STOP_MEANING:
        print(f"  stop 0x{int(stop,16):x} = {STOP_MEANING[stop]}")
    if calls:
        print(f"  call trace: {len(calls)} calls; last 12 before the stop:")
        for l in calls[-12:]: print("   ", l)
        # which known error-returning site was the last one entered?
        tail = [l for l in calls if any(('-> %05x' % t) in l for t in ERR_SITES)]
        if tail:
            print("  last error-site entered:")
            print("   ", tail[-1])
