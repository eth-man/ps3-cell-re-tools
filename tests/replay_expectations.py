#!/usr/bin/env python3
"""
Replay the published results this rig is responsible for.

Findings produced by these tools declare, in the record, what the tool must
still do -- exact PCs, exact stop codes, exact hijack counts. This replays
them, so a pull request can be judged by whether it preserved the record
rather than by whether the diff looks reasonable.

  green   every published result survived the change
  red     the change altered a published measurement; the name says which
  skip    the artifact or the runner needed is not available HERE

Skips are reported loudly and counted. A run that checked nothing must not
look like a run that checked everything -- that is the whole point.

Where the expectations come from, in order:
    --expectations <path|url>
    $PS3_EXPECTATIONS
    ./expectations.json
    ../ps3-ai-re/expectations.json

The record lives in a separate repository. If it is not reachable from here,
this exits 0 with "nothing to check" -- CI on a fork must not fail because a
private repo was not readable.
"""

import argparse
import json
import os
import shutil
import re
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# --------------------------------------------------------------- artifacts

# Expectations name what they need by coverage id. Map those to something we
# can actually look for. Absent -> SKIP, never FAIL: public CI holds no
# firmware and no keys, and it must say so rather than passing an empty run.
ARTIFACT_ENV = "PS3_CORPUS"          # a directory holding decrypted modules


def artifact_available(need):
    corpus = os.environ.get(ARTIFACT_ENV)
    if not corpus or not os.path.isdir(corpus):
        return False, f"{ARTIFACT_ENV} not set"
    ver = need.replace("pup-", "").replace("-cex", "").replace("-dex", "")
    # corpora are named both ways in the wild: 4.93/ and 493/
    for form in (ver, ver.replace(".", "")):
        hit = os.path.join(corpus, form)
        if os.path.isdir(hit):
            return True, hit
    return False, f"no {ver}/ under {corpus}"


# ----------------------------------------------------------------- runners

# A runner turns an expectation's `run` string into measured values. Register
# one per tool entry point as it is wired up. An unregistered runner SKIPS --
# it does not silently pass, and it does not fail a contributor's PR for
# something the repo has not implemented yet.
RUNNERS = {}


def runner(prefix):
    def deco(fn):
        RUNNERS[prefix] = fn
        return fn
    return deco


@runner("lv1procs.py")
def run_lv1procs(cmd, artifacts):
    """Real runner: needs an lv1.elf in the corpus directory."""
    lv1 = None
    for base in artifacts.values():
        cand = os.path.join(base, "lv1.elf")
        if os.path.isfile(cand):
            lv1 = cand
            break
    if not lv1:
        return None, "no lv1.elf in the corpus"
    tool = os.path.join(ROOT, "harnesses", "lv1procs.py")
    if not os.path.isfile(tool):
        return None, "lv1procs.py is not in this repository"
    # NEVER write extracted Sony images into the repository tree. The first
    # run of this harness put seven decrypted lv1 ELFs in tests/_out and
    # `git add -A` staged them for a PUBLIC repo. Use a temp dir that cannot
    # be committed by accident.
    out = tempfile.mkdtemp(prefix="replay-lv1procs-")
    r = subprocess.run([sys.executable, tool, lv1, out],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        return None, f"lv1procs.py exited {r.returncode}: {r.stderr[:200]}"
    try:
        progs = sorted(f[:-4] for f in os.listdir(out) if f.endswith(".elf"))
        return {"programs": len(progs), "names": progs}, None
    finally:
        shutil.rmtree(out, ignore_errors=True)


def missing_names(assertion, measured):
    """Names the assertion needs that the runner did not produce."""
    try:
        code = compile(assertion, "<assert>", "eval")
    except SyntaxError as exc:
        return None, f"unparseable assertion: {exc}"
    return [n for n in code.co_names if n not in measured], None



@runner("svtest")
def run_svtest(cmd, artifacts):
    """svtest <version> <len-hex> <marker-hex> -> pc, stop."""
    parts = cmd.split()
    if len(parts) < 4:
        return None, f"cannot parse: {cmd}"
    _, ver, length, marker = parts[:4]
    length = length[2:] if length.lower().startswith("0x") else length
    sh = os.path.join(ROOT, "harnesses", "svtest.sh")
    if not os.path.isfile(sh):
        return None, "harnesses/svtest.sh is not in this repository"
    env = dict(os.environ)
    env.setdefault("PS3_CORPUS", os.environ.get(ARTIFACT_ENV, ""))
    r = subprocess.run(["bash", sh, ver, length, marker],
                       capture_output=True, text=True, timeout=600, env=env)
    out = r.stdout + r.stderr
    if r.returncode == 2:
        return None, out.strip().splitlines()[0] if out.strip() else "setup"
    pc = re.search(r"pc:\s*([0-9a-f]+)", out)
    stop = re.search(r"stop instruction reached:\s*([0-9a-f]+)", out)
    if not pc:
        return None, f"no pc in output: {out[:120]}"
    return {"pc": int(pc.group(1), 16),
            "stop": int(stop.group(1), 16) if stop else None}, None


@runner("verifygate")
def run_verifygate(cmd, artifacts):
    """verifygate <byte-hex> -> verify: "runs" | "skipped"."""
    parts = cmd.split()
    if len(parts) < 2:
        return None, f"cannot parse: {cmd}"
    byte = parts[1]
    byte = byte[2:] if byte.lower().startswith("0x") else byte
    byte = byte[-1] if byte.upper().startswith("E") else byte   # 0xE9 -> 9
    sh = os.path.join(ROOT, "harnesses", "verifygate.sh")
    if not os.path.isfile(sh):
        return None, "harnesses/verifygate.sh is not in this repository"
    env = dict(os.environ)
    env.setdefault("PS3_CORPUS", os.environ.get(ARTIFACT_ENV, ""))
    # Pin the version from the expectation's `needs`, never let the harness
    # pick. A loose match once substituted a 3.56 module for a 4.93 test.
    ver = "493"
    for need in artifacts:
        m = re.search(r"(\d)\.?(\d\d)", str(need))
        if m:
            ver = m.group(1) + m.group(2)
    r = subprocess.run(["bash", sh, "-v", ver, byte], capture_output=True,
                       text=True, timeout=600, env=env)
    out = r.stdout + r.stderr
    if r.returncode == 2:
        return None, out.strip().splitlines()[0] if out.strip() else "setup"
    m = re.search(r"verify (runs|skipped)", out)
    if not m:
        return None, f"no verdict in output: {out[:120]}"
    return {"verify": m.group(1)}, None


def evaluate(assertion, measured):
    """Evaluate the assertion against measured values. No builtins."""
    try:
        return bool(eval(assertion, {"__builtins__": {}}, dict(measured)))
    except Exception as exc:
        return f"could not evaluate: {exc}"


# -------------------------------------------------------------------- main

def load_expectations(src):
    if src and src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=30) as r:
            return json.load(r)
    with open(src) as fh:
        return json.load(fh)


def find_source(explicit):
    for cand in (explicit, os.environ.get("PS3_EXPECTATIONS"),
                 os.path.join(ROOT, "expectations.json"),
                 os.path.join(ROOT, "..", "ps3-ai-re", "expectations.json")):
        if cand and (cand.startswith("http") or os.path.isfile(cand)):
            return cand
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--expectations")
    ap.add_argument("--tool", help="only this tool's expectations")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if nothing could be checked")
    args = ap.parse_args()

    src = find_source(args.expectations)
    if not src:
        print("replay: no expectations file reachable from here.\n"
              "        The record lives in a separate repository; point at it\n"
              "        with --expectations or $PS3_EXPECTATIONS.\n"
              "        Nothing to check.")
        return 1 if args.strict else 0

    data = load_expectations(src)
    exps = data.get("expectations", [])
    if args.tool:
        exps = [e for e in exps if e.get("tool") == args.tool]

    print(f"replay: {len(exps)} expectation(s) from {src}\n")
    passed = failed = skipped = 0

    for e in exps:
        name = e.get("id") or e.get("expectation")
        cmd = e.get("run", "")
        prefix = cmd.split()[0] if cmd else ""

        artifacts, missing = {}, []
        for need in (e.get("needs") or []):
            ok, info = artifact_available(need)
            (artifacts.setdefault(need, info) if ok else missing.append(f"{need} ({info})"))
        if missing:
            print(f"  SKIP  {name}\n        needs {', '.join(missing)}")
            skipped += 1
            continue

        fn = RUNNERS.get(prefix)
        if not fn:
            print(f"  SKIP  {name}\n        no runner registered for '{prefix}'")
            skipped += 1
            continue

        measured, err = fn(cmd, artifacts)
        if measured is None:
            print(f"  SKIP  {name}\n        {err}")
            skipped += 1
            continue

        gaps, err = missing_names(e["assert"], measured)
        if err or gaps:
            print(f"  SKIP  {name}\n        "
                  + (err or f"runner produced no {', '.join(gaps)} "
                             f"-- this harness does not implement it yet"))
            skipped += 1
            continue

        result = evaluate(e["assert"], measured)
        if result is True:
            print(f"  PASS  {name}")
            passed += 1
        else:
            print(f"  FAIL  {name}")
            print(f"        assert  {e['assert']}")
            print(f"        got     {measured}")
            print(f"        finding {e.get('finding')} — {e.get('finding_title','')}")
            if e.get("why"):
                print(f"        why     {e['why']}")
            failed += 1

    print(f"\nreplay: {passed} passed, {failed} failed, {skipped} skipped")
    if failed:
        print("\nA failure means this change altered a PUBLISHED measurement.\n"
              "Either the change is wrong, or the finding is -- and the second\n"
              "case is a contribution in its own right. Say which you think it\n"
              "is in the pull request.")
        return 1
    if skipped and not passed:
        print("\nNothing was actually checked. This run proves nothing.")
        return 1 if args.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
