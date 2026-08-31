#!/usr/bin/env python3
"""Verify every hashed section of a SELF against its stored digest, offline.

The scheme, established in notes/147 and confirmed two independent ways:

    stored_digest = HMAC-SHA1( key  = keys[sha1_index + 2]   (0x40 bytes),
                               data = the section after AES-128-CTR decryption
                                      with keys[key_index] / keys[iv_index] )

For an unencrypted section (encrypted == 1) the decryption step is the identity,
which is how the scheme was pinned down without needing a cipher at all.

This needs no emulator and no console -- it is a pure offline oracle for SELF
section integrity, usable on any file in the corpus.

VALIDATED, WITH A LIMIT (40 files across 3.55 / 4.20 / 4.93, 125 hashed sections):

    type=2  enc=3  (encrypted program segments)   85 / 85   100%
                                                  (both comp=1 and comp=2)
    type=1  enc=1  (unencrypted header sections)  25 / 40    62%

So the scheme is exact for every encrypted program segment tested, and NOT
reliable for the unencrypted type-1 header sections -- 15 of those mismatch and
the reason is unknown.  A type-1 section sits at the end of the file and abuts
the signature area, so the digest there may cover a different range; that is a
guess and has not been checked.  Trust this oracle on type-2 sections; treat a
type-1 mismatch as unexplained rather than as a corrupt file.

usage: sce_verify.py <file.self> [...]
"""
import sys, os, re, struct, hashlib, hmac
from Crypto.Cipher import AES
from Crypto.Util import Counter

PS3 = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PS3, 'tools'))
from sce_meta import decrypt

def keysets():
    txt = open(os.path.join(PS3, 'tools/scetool/data/keys')).read().replace('\r', '')
    out = []
    for blk in txt.split('[')[1:]:
        name, _, body = blk.partition(']')
        g = dict(re.findall(r'^(\w+)=(\S+)$', body, re.M))
        if 'erk' in g:
            out.append((name.strip(), bytes.fromhex(g['erk']), bytes.fromhex(g['riv'])))
    return out

def verify(path, ks):
    raw = open(path, 'rb').read()
    blob = None
    for fam, erk, riv in ks:
        try:
            blob, info = decrypt(path, erk, riv)
            break
        except Exception:
            continue
    if blob is None:
        return None, "no keyset decrypts the metadata"
    nsec = info['section_count']
    keys = 0x20 + nsec * 0x30
    ok = bad = skipped = 0
    for i in range(nsec):
        f = struct.unpack_from('>QQIIIIIIII', blob, 0x20 + i * 0x30)
        off, size, _t, _i, hashed, sha_i, enc, key_i, iv_i, _c = f
        if hashed != 2 or size == 0:
            skipped += 1; continue
        data = raw[off:off + size]
        if enc == 3:
            k  = blob[keys + key_i * 0x10 : keys + key_i * 0x10 + 0x10]
            iv = blob[keys + iv_i  * 0x10 : keys + iv_i  * 0x10 + 0x10]
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
            data = AES.new(k, AES.MODE_CTR, counter=ctr).decrypt(data)
        hk = blob[keys + (sha_i + 2) * 0x10 : keys + (sha_i + 2) * 0x10 + 0x40]
        want = blob[keys + sha_i * 0x10 : keys + sha_i * 0x10 + 20]
        if hmac.new(hk, data, hashlib.sha1).digest() == want: ok += 1
        else: bad += 1
    return (ok, bad, skipped), fam

if __name__ == '__main__':
    ks = keysets()
    tot_ok = tot_bad = 0
    for p in sys.argv[1:]:
        r, fam = verify(p, ks)
        if r is None:
            print("  %-34s %s" % (os.path.basename(p), fam)); continue
        ok, bad, skip = r
        tot_ok += ok; tot_bad += bad
        print("  %-34s [%s] sections verified=%d FAILED=%d skipped=%d"
              % (os.path.basename(p), fam, ok, bad, skip))
    if len(sys.argv) > 2:
        print("  TOTAL: %d verified, %d failed" % (tot_ok, tot_bad))
