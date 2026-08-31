#!/usr/bin/env python3
"""Classify every build boundary in a component's timeline.

A code-hash difference is a QUESTION, not a finding. `spu_pkg_rvk_verifier`
4.11 -> 4.20 differs by exactly two bytes, both in the destination-register field
of two `il $rN,0` instructions -- semantically identical, a rebuild artifact.
Without this step a hash timeline invents changes.

Classification per boundary:
  same-size + same mnemonic sequence + only register operands differ -> REGALLOC
  mnemonic sequence differs, or sizes differ                         -> SEMANTIC

  boundary_diff.py <component-substring> [--kind CEX]
"""
import os, re, sqlite3, struct, subprocess, sys, tempfile

ROOT = "/opt/projects/ps3"
OBJDUMP = f"{ROOT}/tools/spu-toolchain/bin/spu-elf-objdump"
kind = sys.argv[sys.argv.index("--kind") + 1] if "--kind" in sys.argv else "CEX"
FILES = None
if "--files" in sys.argv:
    i = sys.argv.index("--files")
    FILES = (sys.argv[i + 1], sys.argv[i + 2])
    comp = "(two files)"
else:
    comp = sys.argv[1]

conn = sqlite3.connect(f"{ROOT}/extracted/corpus.db", timeout=120)
conn.execute("PRAGMA busy_timeout=120000")


def vkey(v):
    m = re.match(r"(\d+)\.(\d+)$", v)
    return (int(m.group(1)), int(m.group(2))) if m else (99, 99)


rows = [] if FILES else list(conn.execute("""
   SELECT p.version, d.sha256, c.code_sha FROM file f
     JOIN pup p ON p.id=f.pup_id JOIN dec d ON d.sha256=f.sha256
     JOIN codehash c ON c.out_sha=d.out_sha
    WHERE p.kind=? AND f.path LIKE ? AND c.code_sha IS NOT NULL
    GROUP BY p.version""", (kind, f"%{comp}%")))
rows.sort(key=lambda r: vkey(r[0]))
if not rows and not FILES:
    sys.exit(f"boundary_diff: no decrypted builds match '{comp}' -- nothing to compare")

runs = []
for ver, sha, ch in rows:
    if runs and runs[-1][0] == ch:
        runs[-1][2] = ver
    else:
        runs.append([ch, ver, ver, sha])
if not FILES:
    print(f"{comp}: {len(runs)} distinct code build(s) over {len(rows)} version(s)\n")


def text(path):
    """ALL executable sections concatenated -- must match what codehash.py hashes.

    Returning only the first one reported `text 16 -> 46496 bytes` for a build
    the timeline says is 91624 B, because that image has a small exec section
    ahead of the real one. Two tools disagreeing about what "the code" is makes
    every comparison between them meaningless."""
    d = open(path, "rb").read()
    shoff = struct.unpack(">I", d[0x20:0x24])[0]
    ent = struct.unpack(">H", d[0x2e:0x30])[0]
    n = struct.unpack(">H", d[0x30:0x32])[0]
    out, first = b"", None
    for i in range(n):
        o = shoff + i * ent
        nm, ty, fl, ad, off, sz = struct.unpack(">IIIIII", d[o:o + 24])
        if (fl & 4) and ty == 1 and sz:
            if first is None: first = ad
            out += d[off:off + sz]
    return first, out


def insns(path):
    r = subprocess.run([OBJDUMP, "-d", path], stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, timeout=600)
    out = []
    for l in r.stdout.decode("utf8", "replace").splitlines():
        m = re.match(r"\s*([0-9a-f]+):\t(?:[0-9a-f]{2} ){4}\t(\S+)\s*(.*?)\s*$", l)
        if m:
            out.append((int(m.group(1), 16), m.group(2), m.group(3).split("#")[0].strip()))
    return out


REG = re.compile(r"\$\d+")
sem = reg = 0


def compare(pa, pb, label):
    global sem, reg
    va1, t1 = text(pa); va2, t2 = text(pb)
    if len(t1) != len(t2):
        print(f"  SEMANTIC  {label:<24s} text {len(t1)} -> {len(t2)} bytes"); sem += 1; return
    ia, ib = insns(pa), insns(pb)
    mn_a = [x[1] for x in ia]; mn_b = [x[1] for x in ib]
    if mn_a != mn_b:
        # A POSITIONAL count is misleading: one inserted instruction makes every
        # later one compare unequal, so a relocation looks like a total rewrite.
        # Measure shift-tolerant similarity too before calling anything a rewrite.
        n = sum(1 for x, y in zip(mn_a, mn_b) if x != y)
        import difflib
        # quick_ratio compares the instruction MULTISET, i.e. "is the same mix of
        # instructions present", which is order-insensitive. Combined with the
        # positional count it separates three cases that a single number cannot.
        mix = difflib.SequenceMatcher(None, mn_a, mn_b, autojunk=False).quick_ratio()
        frac = n / max(1, len(mn_a))
        if frac < 0.01:
            kind = f"small edit ({n} instruction(s))"
        elif mix > 0.98:
            kind = "same instruction mix, shifted -- relocation/reordering, not a rewrite"
        elif mix > 0.80:
            kind = "mostly shared instruction mix"
        else:
            kind = "substantial rewrite"
        print(f"  SEMANTIC  {label:<24s} {n} of {len(mn_a)} differ positionally, "
              f"instruction-mix {mix:.3f} -- {kind}")
        sem += 1; return
    # same mnemonics: is the only difference in register fields?
    diffs = [(x, y) for x, y in zip(ia, ib) if x[2] != y[2]]
    if not diffs:
        print(f"  IDENTICAL {label:<24s} same code"); return
    onlyreg = all(REG.sub("$", x[2]) == REG.sub("$", y[2]) for x, y in diffs)
    if onlyreg:
        print(f"  REGALLOC  {label:<24s} {len(diffs)} instruction(s) differ only in "
              f"register operands -- semantically identical")
        for x, y in diffs[:4]:
            print(f"                {x[0]:#07x}  {x[1]} {x[2]}   ->   {y[1]} {y[2]}")
        reg += 1
    else:
        print(f"  SEMANTIC  {label:<24s} {len(diffs)} instruction(s) differ in non-register operands")
        for x, y in diffs[:4]:
            print(f"                {x[0]:#07x}  {x[1]} {x[2]}   ->   {y[1]} {y[2]}")
        sem += 1


if FILES:
    compare(FILES[0], FILES[1], "A -> B")
else:
    for i in range(len(runs) - 1):
        a, b = runs[i], runs[i + 1]
        pa, pb = f"{ROOT}/extracted/dec/{a[3]}.elf", f"{ROOT}/extracted/dec/{b[3]}.elf"
        if os.path.exists(pa) and os.path.exists(pb):
            span = lambda r: r[1] if r[1] == r[2] else f"{r[1]}-{r[2]}"
            compare(pa, pb, f"{span(a)} -> {span(b)}")
print(f"\n{sem} semantic boundary(ies), {reg} register-allocation-only")
