#!/usr/bin/env python3
"""Hash only the EXECUTABLE segments of every decrypted ELF.

Whole-file hashes are useless for a change timeline: Sony bumps version counters
and rotates embedded key material every release, so the decrypted plaintext
differs even when not one instruction changed (notes/01 measured exactly that for
3.55 -> 3.56). Hashing the PF_X segments answers "did the CODE change".
"""
import os, sqlite3, struct, hashlib, sys

ROOT = "/opt/projects/ps3"
DEC = f"{ROOT}/extracted/dec"
conn = sqlite3.connect(f"{ROOT}/extracted/corpus.db", timeout=180)
conn.execute("PRAGMA journal_mode=WAL"); conn.execute("PRAGMA busy_timeout=180000")
conn.execute("""CREATE TABLE IF NOT EXISTS codehash(
    out_sha TEXT PRIMARY KEY, code_sha TEXT, code_size INT, machine INT, note TEXT)""")
conn.commit()


def _sections(d, cls):
    """(offset, size, flags) for every section, or [] if there are no headers."""
    try:
        if cls == 1:
            shoff = struct.unpack(">I", d[0x20:0x24])[0]
            ent = struct.unpack(">H", d[0x2e:0x30])[0]
            n = struct.unpack(">H", d[0x30:0x32])[0]
            out = []
            for i in range(n):
                o = shoff + i * ent
                nm, ty, fl, ad, off, sz = struct.unpack(">IIIIII", d[o:o + 24])
                out.append((off, sz, fl, ty))
            return out
        shoff = struct.unpack(">Q", d[0x28:0x30])[0]
        ent = struct.unpack(">H", d[0x3a:0x3c])[0]
        n = struct.unpack(">H", d[0x3c:0x3e])[0]
        out = []
        for i in range(n):
            o = shoff + i * ent
            nm, ty = struct.unpack(">II", d[o:o + 8])
            fl, ad, off, sz = struct.unpack(">QQQQ", d[o + 8:o + 40])
            out.append((off, sz, fl, ty))
        return out
    except Exception:
        return []


def exec_hash(path):
    d = open(path, "rb").read()
    if d[:4] != b"\x7fELF":
        return None, 0, 0, "not-elf"
    cls, enc = d[4], d[5]
    if enc != 2:
        return None, 0, 0, "little-endian"
    mach = struct.unpack(">H", d[18:20])[0]
    h = hashlib.sha256()
    total = 0
    # Prefer SECTION granularity.  These images have one PF_X *segment* spanning
    # both .text and .rodata, and Sony bumps a version counter in .rodata every
    # release -- lv1ldr 4.86 vs 4.91 differ by exactly ONE byte, at VA 0x26e93,
    # inside rodata.  A segment-level hash therefore reports a new build every
    # release when not one instruction changed.
    secs = _sections(d, cls)
    execs = [(off, sz) for off, sz, fl, ty in secs
             if (fl & 0x4) and ty == 1 and sz]          # SHF_EXECINSTR, SHT_PROGBITS
    if execs:
        for off, sz in execs:
            h.update(d[off:off + sz]); total += sz
        return h.hexdigest(), total, mach, "sect"
    try:
        if cls == 1:      # ELF32 (SPU)
            phoff = struct.unpack(">I", d[0x1c:0x20])[0]
            ent = struct.unpack(">H", d[0x2a:0x2c])[0]
            n = struct.unpack(">H", d[0x2c:0x2e])[0]
            for i in range(n):
                o = phoff + i * ent
                t, off, va, pa, fsz, msz, fl, al = struct.unpack(">IIIIIIII", d[o:o + 32])
                if t == 1 and (fl & 1):
                    h.update(d[off:off + fsz]); total += fsz
        else:             # ELF64 (PPC64)
            phoff = struct.unpack(">Q", d[0x20:0x28])[0]
            ent = struct.unpack(">H", d[0x36:0x38])[0]
            n = struct.unpack(">H", d[0x38:0x3a])[0]
            for i in range(n):
                o = phoff + i * ent
                t, fl = struct.unpack(">II", d[o:o + 8])
                off, va, pa, fsz, msz, al = struct.unpack(">QQQQQQ", d[o + 8:o + 56])
                if t == 1 and (fl & 1):
                    h.update(d[off:off + fsz]); total += fsz
    except Exception as e:
        return None, 0, mach, f"parse:{e!r}"[:60]
    if total == 0:
        return None, 0, mach, "no-exec-segment"
    return h.hexdigest(), total, mach, ""


def main():
    done = {r[0] for r in conn.execute("SELECT out_sha FROM codehash")}
    todo = [r for r in conn.execute("SELECT sha256, out_sha FROM dec WHERE status='ok'")
            if r[1] and r[1] not in done]
    print(f"{len(done)} hashed, {len(todo)} to do", flush=True)
    n = ok = 0
    for sha, out_sha in todo:
        p = f"{DEC}/{sha}.elf"
        if not os.path.exists(p):
            continue
        ch, sz, mach, note = exec_hash(p)
        conn.execute("INSERT OR REPLACE INTO codehash VALUES(?,?,?,?,?)", (out_sha, ch, sz, mach, note))
        n += 1; ok += ch is not None
        if n % 100 == 0:
            conn.commit(); print(f"  {n}/{len(todo)}", flush=True)
    conn.commit()
    print(f"done: {n} files, {ok} with an executable segment")
    for note, c in conn.execute("SELECT note,count(*) FROM codehash GROUP BY note ORDER BY 2 DESC LIMIT 6"):
        print(f"  {note or '(ok)':20s} {c}")


if __name__ == "__main__":
    main()
