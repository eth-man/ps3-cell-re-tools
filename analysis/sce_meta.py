#!/usr/bin/env python3
"""Decrypt an SCE file's metadata (header + section headers + keys + optional
headers) offline, for injection into the isoldr harness.

THE TRAP THIS EXISTS TO AVOID: `scetool -i` prints the metadata Key and IV, and
the IV IT PRINTS IS WRONG FOR DECRYPTION.  PolarSSL's aes_crypt_ctr MUTATES the
nonce counter in place, so scetool displays the counter AFTER the run:

    real IV            b0db5253217af4061ec3902c987317_60
    scetool prints     b0db5253217af4061ec3902c987317_9b     (60 + 0x3B blocks)

Only the last byte differs, so it looks right and silently decrypts to garbage.
Derive the IV yourself instead:

    1. metadata_info at 0x20 + metadata_offset, 0x40 bytes,
       AES-256-CBC with the keyset's erk/riv   (erk is 32 bytes -- AES-256)
    2. key = info[0x00:0x10], iv = info[0x20:0x30]; both pads must be zero
    3. metadata headers at 0x20 + metadata_offset + 0x40, length
       header_len - that offset, AES-128-CTR with key/iv

Usage:  sce_meta.py <file.self> <erk-hex> <riv-hex> [out.bin]
"""
import sys, struct
from Crypto.Cipher import AES
from Crypto.Util import Counter

def decrypt(path, erk, riv):
    f = open(path, 'rb').read()
    mo = struct.unpack_from('>I', f, 0x0C)[0]
    hl = struct.unpack_from('>Q', f, 0x10)[0]
    off = 0x20 + mo
    info = AES.new(erk, AES.MODE_CBC, riv).decrypt(f[off:off + 0x40])
    key, kpad, iv, ipad = info[0:16], info[16:32], info[32:48], info[48:64]
    if kpad[0] or ipad[0]:
        raise ValueError("metadata_info pads are non-zero -- wrong keyset")
    start, size = off + 0x40, hl - (off + 0x40)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'))
    pt = AES.new(key, AES.MODE_CTR, counter=ctr).decrypt(f[start:start + size])
    sig, unk0, nsec, nkey, opt = struct.unpack_from('>QIIII', pt, 0)
    total = 0x20 + nsec * 0x30 + nkey * 0x10 + opt
    return pt[:total], dict(sig_input_length=sig, unknown_0=unk0,
                            section_count=nsec, key_count=nkey,
                            opt_header_size=opt, total=total)

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    blob, info = decrypt(sys.argv[1], bytes.fromhex(sys.argv[2]),
                         bytes.fromhex(sys.argv[3]))
    for k, v in info.items():
        print("  %-18s 0x%X" % (k, v))
    if len(sys.argv) > 4:
        open(sys.argv[4], 'wb').write(blob)
        print("  wrote %s (%d bytes)" % (sys.argv[4], len(blob)))
