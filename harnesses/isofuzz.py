#!/usr/bin/env python3
"""Drive any isolated SPU module from its real entry with the documented ABI and
look for control-flow hijack.

ABI (psdevwiki 'Iso module'): r3..r6 = iso_module_arg0..3, r7..r22 = indiv_data,
r23 = entry point, r24 = forced_sdk_minver.  We do not know which argument is a
length for every module, so sweep: each of arg0..arg3 in turn plays the length
while another plays a host effective address.

  isofuzz.py <module.elf> [--marker 3BEE0] [--sdk 420]
"""
import itertools, os, re, struct, subprocess, sys, tempfile

# Below this many distinct instructions, a run never got past module init and a
# "no hijack" result carries no information.
COVER_FLOOR = 150
# Addresses the experiment is actually about. Total coverage says the run went
# somewhere; reaching these says it went where the question lives.
REACH = []

ROOT = "/opt/projects/ps3"
elf = sys.argv[1]
MARK = int(sys.argv[sys.argv.index("--marker") + 1], 16) if "--marker" in sys.argv else 0x0003BEE0
SDK = sys.argv[sys.argv.index("--sdk") + 1] if "--sdk" in sys.argv else "420"
if "--reach" in sys.argv:
    REACH = [x.strip() for x in sys.argv[sys.argv.index("--reach") + 1].split(",") if x.strip()]

ea = bytearray(0x8000)
pat = bytearray(b"B" * 0x1000)
for off in range(0, 0x1000, 4):        # marker everywhere: any LR slot lands on it
    struct.pack_into(">I", pat, off, MARK)
ea[0x1000:0x1000 + len(pat)] = pat
f = tempfile.NamedTemporaryFile(delete=False, suffix=".ea"); f.write(ea); f.close()

hits, runs, covs, reached = [], 0, [], set()
LENS = ["400", "1000", "4000"]
for lenarg, eaarg in itertools.permutations(range(4), 2):
    for L in LENS:
        regs = {}
        for i in range(4):
            regs[3 + i] = f"0:{SDK}:0:0"          # default: a plausible version/size
        regs[3 + eaarg] = "0:1000:0:0"
        regs[3 + lenarg] = f"0:{L}:0:0"
        cmd = [os.environ.get("ANERG_BIN", f"{ROOT}/tools/anergistic/anergistic")]
        for r, v in regs.items():
            cmd += ["-r", f"{r}={v}"]
        for r in range(7, 25):
            cmd += ["-r", f"{r}=0"]
        cmd += ["-m", "600000", elf]
        try:
            env = dict(os.environ, ANERG_EA=f.name, ANERG_COVER="1")
            if REACH: env["ANERG_COVER_WANT"] = ",".join(REACH)
            p = subprocess.run(cmd, env=env,
                               timeout=90, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except subprocess.TimeoutExpired:
            continue
        runs += 1
        out = p.stdout.decode("utf8", "replace")
        pc = None
        for l in out.splitlines():
            if l.startswith(" pc:"): pc = l.split()[1]
        m = re.search(r"\[COVER\] (\d+)", out)
        if m: covs.append(int(m.group(1)))
        for a, yn in re.findall(r"\[REACHED\] (\S+) (YES|NO)", out):
            if yn == "YES": reached.add(a.lstrip("0") or "0")
        if pc == "%08x" % MARK:
            hits.append((lenarg, eaarg, L, pc))
os.unlink(f.name)
name = os.path.basename(elf)
best = max(covs) if covs else 0
print(f"{name}: {runs} runs, {len(hits)} hijack(s), best coverage {best} instrs")
for lenarg, eaarg, L, pc in hits:
    print(f"    HIJACK  arg{lenarg}=0x{L} (length)  arg{eaarg}=0x1000 (EA)  pc={pc}")
if REACH:
    for a in REACH:
        k = a.lstrip("0") or "0"
        print(f"    site 0x{a}: {'REACHED' if k in reached else 'NEVER REACHED'}")
if not hits:
    missed = [a for a in REACH if (a.lstrip("0") or "0") not in reached]
    if REACH and missed:
        print(f"    *** INCONCLUSIVE *** never reached {', '.join('0x'+a for a in missed)} -- "
              f"0 hijacks says nothing about code that did not execute")
    elif best < COVER_FLOOR:
        print(f"    *** INCONCLUSIVE *** best coverage {best} < {COVER_FLOOR} instructions -- "
              f"the module never got past its init/handshake")
    else:
        print(f"    negative is meaningful: {best} instructions reached"
              + (f", including every site in --reach" if REACH else ""))
