#!/usr/bin/env python3
"""Extract lv1's embedded userland programs from an lv1.elf.

lv1 carries an uncompressed archive of seven programs (pme_init, sysmgr_ss,
ss_init, updater_frontend, ss_server1..3) as a data blob.  They are UNENCRYPTED
fSELFs; the ELF starts 0x178 into each.  Their section headers point past the
end of the archived copy, so e_shoff/e_shnum/e_shstrndx are zeroed on the way
out and the caller should disassemble PT_LOAD segments directly, e.g.

    objdump -D -b binary -m powerpc:common64 -EB --adjust-vma=0x80000000 x.text

Usage: lv1procs.py <lv1.elf> <outdir>
"""
import os, struct, sys

def segments(d):
    phoff = struct.unpack(">Q", d[0x20:0x28])[0]
    ent = struct.unpack(">H", d[0x36:0x38])[0]
    nph = struct.unpack(">H", d[0x38:0x3a])[0]
    out = []
    for i in range(nph):
        o = phoff + i * ent
        t, fl = struct.unpack(">II", d[o:o + 8])
        off, va, pa, fsz, msz, al = struct.unpack(">QQQQQQ", d[o + 8:o + 56])
        if t == 1:
            out.append((off, va, fsz))
    return out


def find_archive(d):
    """The blob is the segment containing the literal name table."""
    for off, va, fsz in segments(d):
        blob = d[off:off + fsz]
        if b"ss_server1.fself" in blob and b"pme_init" in blob:
            return blob, va
    raise SystemExit("no embedded-process archive found")


def parse(blob):
    """Header: {u32 count, u32 data_start}, then `count` records of
    {u32 name_off, u32 offset, u32 size}, then a NUL-separated name table."""
    n = struct.unpack(">I", blob[0:4])[0]
    if not 1 <= n <= 64:
        raise SystemExit("implausible entry count %d" % n)
    ntab_off = 8 + 12 * n
    ents = []
    for k in range(n):
        no, off, sz = struct.unpack(">III", blob[8 + 12 * k:8 + 12 * k + 12])
        name = blob[ntab_off + no:blob.index(b"\0", ntab_off + no)].decode()
        ents.append((name, off, sz))
    return ents


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    d = open(sys.argv[1], "rb").read()
    outdir = sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    blob, va = find_archive(d)
    ents = parse(blob)
    print("archive at VA 0x%x, %d entries" % (va, len(ents)))
    for nm, o, s in ents:
        b = blob[o:o + s]
        nm = nm.replace(".fself", "")
        j = b.find(b"\x7fELF")
        if j < 0:
            open(os.path.join(outdir, nm + ".bin"), "wb").write(b)
            print("  %-18s 0x%06x +0x%06x  (not an ELF)" % (nm, o, s))
            continue
        e = bytearray(b[j:])
        e[6] = 1                                  # EI_VERSION
        e[7] = 0                                  # EI_OSABI (Sony uses 0x66)
        struct.pack_into(">Q", e, 0x28, 0)        # e_shoff
        struct.pack_into(">H", e, 0x3c, 0)        # e_shnum
        struct.pack_into(">H", e, 0x3e, 0)        # e_shstrndx
        pth = os.path.join(outdir, nm + ".elf")
        open(pth, "wb").write(bytes(e))
        segs = ["0x%x@0x%x" % (fs, v) for _, v, fs in segments(bytes(e))]
        print("  %-18s 0x%06x +0x%06x -> %s  loads %s" % (nm, o, s, pth, segs))


if __name__ == "__main__":
    main()
