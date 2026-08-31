#!/usr/bin/env python3
"""Run the stack-copy detector over every decrypted SPU binary in the corpus.

Groups results by (module, candidate signature) so one finding does not appear
once per firmware version.
"""
import os, re, struct, subprocess, sqlite3, collections, sys

ROOT = "/opt/projects/ps3"
DEC = f"{ROOT}/extracted/dec"
OBJDUMP = f"{ROOT}/tools/spu-toolchain/bin/spu-elf-objdump"
ASMDIR = "/tmp/claude-1000/-opt-projects-ps3/asm"
os.makedirs(ASMDIR, exist_ok=True)

conn = sqlite3.connect(f"{ROOT}/extracted/corpus.db", timeout=120)
conn.execute("PRAGMA busy_timeout=120000")
# sha -> set of (version, basename)
prov = collections.defaultdict(set)
# the decrypted file is named after the INPUT blob sha, not out_sha
for ver, kind, path, sha in conn.execute("""
        SELECT p.version, p.kind, f.path, d.sha256 FROM file f
          JOIN pup p ON p.id=f.pup_id JOIN dec d ON d.sha256=f.sha256
         WHERE d.status='ok'"""):
    prov[sha].add((kind, ver, os.path.basename(path)))

files = [f for f in os.listdir(DEC) if f.endswith(".elf")]
print(f"{len(files)} decrypted ELFs", flush=True)
spu = 0
found = collections.defaultdict(list)
for i, fn in enumerate(files):
    p = os.path.join(DEC, fn)
    try:
        h = open(p, "rb").read(20)
    except Exception:
        continue
    if h[:4] != b"\x7fELF":
        continue
    mach = struct.unpack(">H", h[18:20])[0]
    if mach != 23:            # EM_SPU
        continue
    spu += 1
    asm = os.path.join(ASMDIR, fn + ".asm")
    if not os.path.exists(asm):
        with open(asm, "w") as o:
            subprocess.run([OBJDUMP, "-d", p], stdout=o,
                           stderr=subprocess.DEVNULL, timeout=300)
    r = subprocess.run([sys.executable, f"{ROOT}/tools/stackcopy_scan.py", asm],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=300)
    for l in r.stdout.decode("utf8", "replace").splitlines():
        if "CANDIDATE" in l:
            m = re.match(r'\s*0x(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)', l)
            if not m: continue
            site, frame, dst, slack, mn, ops = m.groups()
            sha = fn[:-4]
            names = {n for _, _, n in prov.get(sha, set())} or {"?"}
            key = (tuple(sorted(names)), frame, dst, slack, mn, ops)
            found[key].append((sha, site))
print(f"{spu} SPU ELFs scanned, {len(found)} distinct candidate(s)\n", flush=True)

# Built-in positive control. The sv_iso 4.20 overflow (frame 320, dst 112,
# slack 224) is a known-present finding; if the sweep does not rediscover it the
# sweep is broken and its "candidates" -- especially its absences -- mean nothing.
ctl = [k for k in found if k[1] == "320" and k[2] == "112" and k[3] == "224"]
if ctl:
    print("  positive control OK: rediscovered the known sv_iso 4.20 bug "
          "(frame=320 dst=112 slack=224)\n", flush=True)
elif spu:
    print("  *** POSITIVE CONTROL FAILED *** the known sv_iso 4.20 bug was NOT "
          "rediscovered -- do not trust any result below, especially the absences\n",
          flush=True)
rows = sorted(found.items(), key=lambda kv: (int(kv[0][3]) if kv[0][3].isdigit() else 9999))
for (names, frame, dst, slack, mn, ops), hits in rows:
    vers = set()
    for sha, _ in hits:
        for kind, ver, _ in prov.get(sha, set()):
            vers.add(f"{kind}{ver}")
    def vk(v):
        m = re.search(r'(\d+)\.(\d+)', v)
        return (int(m.group(1)), int(m.group(2))) if m else (99, 99)
    vs = sorted(vers, key=vk)
    print(f"  {'/'.join(names)}")
    print(f"     frame={frame} dst={dst} slack={slack}  len<- {mn} {ops}")
    print(f"     {len(hits)} build(s), versions: {' '.join(vs[:14])}{' ...' if len(vs) > 14 else ''}\n")
