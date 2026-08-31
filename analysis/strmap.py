#!/usr/bin/env python3
"""Harvest Sony's own C++ symbol names from diagnostic strings across the corpus.

Debug builds (and some retail ones) carry strings like
`ss_iso_dma_data::get: DMA data seqno error`. Those are the original class and
method names, and they name the architecture far better than any name we invent.
3.60 stripped most of them under Local Store pressure (notes/69), so the DEX and
pre-3.60 builds are where they survive.

  strmap.py harvest              scan every decrypted ELF, collect C++-looking names
  strmap.py refs <elf>           map each string to the code that references it
"""
import os, re, sqlite3, struct, sys, collections

ROOT = "/opt/projects/ps3"
DEC = f"{ROOT}/extracted/dec"
CPP = re.compile(rb"[A-Za-z_][A-Za-z0-9_]{2,}::[A-Za-z_][A-Za-z0-9_]{2,}")
PRINTF = re.compile(rb"[ -~]{8,}")


def strings_of(path, minlen=8):
    d = open(path, "rb").read()
    return d, [(m.start(), m.group()) for m in re.finditer(rb"[ -~]{%d,}" % minlen, d)]


def harvest():
    conn = sqlite3.connect(f"{ROOT}/extracted/corpus.db", timeout=120)
    conn.execute("PRAGMA busy_timeout=120000")
    prov = collections.defaultdict(set)
    for ver, kind, path, sha in conn.execute("""
            SELECT p.version,p.kind,f.path,d.sha256 FROM file f
              JOIN pup p ON p.id=f.pup_id JOIN dec d ON d.sha256=f.sha256
             WHERE d.status='ok'"""):
        prov[sha].add((kind, ver, os.path.basename(path)))
    names = collections.defaultdict(set)
    n = 0
    for fn in os.listdir(DEC):
        if not fn.endswith(".elf"):
            continue
        p = os.path.join(DEC, fn)
        if os.path.getsize(p) > 12 << 20:
            continue
        try:
            d = open(p, "rb").read()
        except Exception:
            continue
        n += 1
        who = prov.get(fn[:-4], set())
        mods = {m for _, _, m in who} or {"?"}
        for m in CPP.finditer(d):
            names[m.group().decode("ascii", "replace")] |= mods
    print(f"scanned {n} decrypted ELFs, found {len(names)} distinct C++ symbol names\n")
    byclass = collections.defaultdict(set)
    for full, mods in names.items():
        byclass[full.split("::")[0]].add((full, tuple(sorted(mods))))
    for cls in sorted(byclass, key=lambda c: -len(byclass[c])):
        ms = sorted(byclass[cls])
        allmods = sorted({m for _, mm in ms for m in mm})
        print(f"{cls}   ({len(ms)} method(s))   seen in: {', '.join(allmods)[:80]}")
        for full, _ in ms:
            print(f"    {full}")
        print()


def refs(elf):
    d, ss = strings_of(elf)
    # SPU: an ila loads an 18-bit address; find which instructions point at each string
    ins = {}
    for i in range(0, len(d) - 3, 4):
        ins[i] = struct.unpack(">I", d[i:i + 4])[0]
    # map file offset -> vaddr via program headers
    phoff = struct.unpack(">I", d[0x1c:0x20])[0]
    ent = struct.unpack(">H", d[0x2a:0x2c])[0]
    nph = struct.unpack(">H", d[0x2c:0x2e])[0]
    segs = []
    for i in range(nph):
        o = phoff + i * ent
        t, off, va, pa, fsz, msz, fl, al = struct.unpack(">IIIIIIII", d[o:o + 32])
        if t == 1:
            segs.append((off, va, fsz))
    def f2v(f):
        for off, va, fsz in segs:
            if off <= f < off + fsz:
                return va + (f - off)
    targets = {}
    for off, s in ss:
        v = f2v(off)
        if v is not None:
            targets[v] = s.decode("ascii", "replace")
    print(f"{os.path.basename(elf)}: {len(targets)} string(s) in loaded segments")
    for foff, word in ins.items():
        if (word >> 25) != 0x21:          # ila
            continue
        imm = (word >> 7) & 0x3FFFF
        if imm in targets:
            va = f2v(foff)
            print(f"  code 0x{va:05x}  ila -> 0x{imm:05x}  {targets[imm][:70]!r}")


if __name__ == "__main__":
    if sys.argv[1] == "harvest":
        harvest()
    else:
        refs(sys.argv[2])
