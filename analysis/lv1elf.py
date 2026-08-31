#!/usr/bin/env python3
"""Wrap a raw lv1 memory dump in a minimal PPC64 big-endian ELF so that
llvm-objdump / readelf can disassemble arbitrary ranges of it.

    tools/lv1elf.py nordumps/xxx.BIN /tmp/lv1.elf [base_vaddr]

Then:
    llvm-objdump-18 -d --start-address=0x306d64 --stop-address=0x306e00 /tmp/lv1.elf
"""
import struct, sys

def build(raw, base=0):
    EHSZ, PHSZ, SHSZ = 64, 56, 64
    nsh = 3                                  # NULL, .text, .shstrtab
    shstr = b"\0.text\0.shstrtab\0"
    off_data = EHSZ + PHSZ
    off_shstr = off_data + len(raw)
    off_sh = (off_shstr + len(shstr) + 15) & ~15

    e = bytearray()
    e += b"\x7fELF" + bytes([2, 2, 1, 0]) + b"\0"*8   # ELF64, MSB, v1, SysV
    e += struct.pack(">HHIQQQIHHHHHH",
                     2,        # ET_EXEC
                     21,       # EM_PPC64
                     1,        # version
                     base,     # entry
                     EHSZ,     # phoff
                     off_sh,   # shoff
                     0,        # flags
                     EHSZ, PHSZ, 1,          # ehsize, phentsize, phnum
                     SHSZ, nsh, 2)           # shentsize, shnum, shstrndx
    assert len(e) == EHSZ
    e += struct.pack(">IIQQQQQQ", 1, 5, off_data, base, base,
                     len(raw), len(raw), 0x10000)      # PT_LOAD, R+X
    assert len(e) == off_data
    e += raw
    e += shstr
    e += b"\0" * (off_sh - len(e))
    e += b"\0" * SHSZ                                   # SHT_NULL
    e += struct.pack(">IIQQQQIIQQ", 1, 1, 0x6, base, off_data,
                     len(raw), 0, 0, 16, 0)             # .text  ALLOC|EXEC
    e += struct.pack(">IIQQQQIIQQ", 7, 3, 0, 0, off_shstr,
                     len(shstr), 0, 0, 1, 0)            # .shstrtab
    return bytes(e)

if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    base = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
    open(dst, "wb").write(build(open(src, "rb").read(), base))
    print(f"{dst}: wrapped {src} at vaddr {base:#x}")
