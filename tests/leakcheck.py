#!/usr/bin/env python3
"""
leakcheck.py -- the publication gate for the PS3 AI RE Project.

Nothing reaches this repository unless it passes here. The gate is an
ALLOWLIST on file type and a set of hard blocks on anything key-shaped.

Design note, because it is not obvious:

  The project's PURPOSE is to describe things like EID0, IDPS and klicensee.
  So a keyword alone is never a violation -- blocking the word would make the
  repository unable to name its own subject. What is blocked is a key-shaped
  VALUE. It is not the word, it is the bytes next to the word.

  Digests are required by the schema and are themselves hex, so a hex run is
  permitted only when it is LABELLED as a digest. That single rule separates
  "sha256: 9f2c..." (the point of the project) from a pasted key (the end of
  it), and has the side effect of keeping every digest in the repo labelled.

Usage:
    leakcheck.py --staged      # git staged files (pre-commit hook)
    leakcheck.py --all         # whole working tree (CI)
    leakcheck.py PATH [PATH..] # explicit paths
Exit: 0 clean, 1 violations found, 2 usage error.
"""

import argparse
import math
import os
import re
import string
import subprocess
import sys

# ---------------------------------------------------------------- allowlist

# Text formats the repository is made of. Anything else is refused by type.
ALLOWED_EXT = {
    ".md", ".yml", ".yaml", ".json", ".txt", ".py", ".c", ".h", ".s", ".S",
    ".sh", ".toml", ".cfg", ".ini", ".csv", ".tsv", ".gitignore",
    ".gitattributes", ".sha256", ".editorconfig", ".java", ".mdc", ".mk", ".in",
}
ALLOWED_NAMES = {
    "LICENSE", "LICENSE-DATA", "AGENTS.md", "CLAUDE.md", "Makefile",
    "CODEOWNERS", ".gitignore", ".gitattributes", "SHA256SUMS", "re",
    "README", "COPYING", "NOTICE", "AUTHORS", "CHANGELOG", "INSTALL", "TODO",
    ".leakcheck-allow",   # the allowlist file must itself be allowed
}

# Explicitly named, so the error message can say WHY rather than "bad type".
DENY_EXT = {
    ".bin": "raw dump or binary blob",
    ".pup": "Sony firmware package -- never redistribute; publish derived facts",
    ".self": "signed Sony executable", ".sprx": "signed Sony library",
    ".prx": "Sony library", ".elf": "compiled binary", ".pkg": "package",
    ".iso": "disc image", ".norbin": "NOR flash dump", ".nandbin": "NAND dump",
    ".dump": "memory dump", ".img": "disk image", ".core": "core dump",
    ".rif": "per-console licence", ".rap": "per-console licence",
    ".edat": "encrypted data", ".pfd": "protected file database",
    ".so": "shared object", ".o": "object file", ".a": "static library",
    ".zip": "archive -- commit the derived facts, not the container",
    ".gz": "archive", ".xz": "archive", ".7z": "archive", ".tar": "archive",
    ".png": "image -- describe the structure in text instead",
    ".jpg": "image", ".gif": "image", ".pdf": "document",
}

# Filenames that are per-console secrets whatever their extension.
DENY_NAME_RE = re.compile(
    r"(^|[^a-z0-9])(idps|eid0|eid_root_key|per[-_]?console|klicensee|"
    r"act\.dat|dev_flash|metldr|bootldr|isoldr|appldr|lv0ldr|lv1ldr|lv2ldr)"
    r"([^a-z0-9]|$)", re.I)
# ...but only for files that could actually BE a dump. Prose and SOURCE may be
# named after their subject: `isoldr_harness.py` is a tool, `metldr-notes.md`
# is prose. The rule was written for `metldr.bin` and over-reached into both.
NAMEABLE_EXT = {".md", ".txt", ".yml", ".yaml", ".json", ".py", ".c", ".h",
                ".s", ".S", ".sh", ".java", ".mdc", ".cfg", ".ini", ".toml"}

# ------------------------------------------------------------- value shapes

# A hex run long enough to be a key: 32 nibbles = AES-128, 64 = AES-256.
HEX_RUN = re.compile(r"(?<![0-9a-fA-Fx])([0-9a-fA-F]{32,})(?![0-9a-fA-F])")
# md5, sha1, sha224, sha256, sha384, sha512 -- in nibbles.
DIGEST_WIDTHS = {32, 40, 56, 64, 96, 128}
# Labelled-digest context. A hex run is permitted only on such a line.
DIGEST_CTX = re.compile(r"\b(sha256|sha512|sha1|md5|digest|checksum|"
                        r"hash|sha256sum|fingerprint)\b", re.I)
# Long base64 -- the other way bytes get pasted into text.
B64_RUN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{48,}={0,2})"
                     r"(?![A-Za-z0-9+/])")
# C-style byte arrays: { 0x9f, 0x2c, ... } -- a key in disguise.
BYTE_ARRAY = re.compile(r"(0x[0-9a-fA-F]{2}\s*,\s*){15,}")
# The way binary really appears in .py/.c source: b"\x9f\x2c\x11..."
ESCAPED_BYTES = re.compile(r"(\\x[0-9a-fA-F]{2}){8,}")
# The catch-all entropy rule fires on regex sources and minified data alike, so
# it applies to prose and data files only. Source files are covered by the
# hex, base64, byte-array and escaped-byte rules, which is where a key in code
# would actually live.
ENTROPY_EXT = {".md", ".txt", ".yml", ".yaml", ".json", ".csv", ".tsv"}
# Characters an encoded blob can contain. A token holding anything else --
# brackets, quotes, parentheses, colons -- is code or a path, not a payload.
# Built rather than written out: a 52-character alphabet literal IS a base64
# blob, and this file's own rules flag it. Correctly.
BLOB_CHARS = set(string.ascii_letters + string.digits + "+/=_-")

# Secret nouns. Harmless alone; damning beside a value.
SECRET_WORD = re.compile(
    r"\b(idps|psid|openpsid|eid[0-4]|eid_root|klicensee|klic|npdrm|"
    r"act\.dat|rif|rap|private[_ ]?key|priv[_ ]?key|secret[_ ]?key|"
    r"master[_ ]?key|per[- _]?console[_ ]?key|erk|riv|pub|ecdsa[_ ]?priv|"
    r"root[_ ]?key|syscon[_ ]?seed|token[_ ]?seed)\b", re.I)

def load_local_allow(root="."):
    """Extra allowed extensions/filenames, one per line, from .leakcheck-allow.

    Keeps the allowlist STRICT by default while letting a project declare its
    own text formats (anergistic's `instrs` table, say). The exception lives
    in the repo where a reviewer sees it in the diff, instead of accumulating
    in this file for every project that shares the gate.
    """
    path = os.path.join(root, ".leakcheck-allow")
    if not os.path.isfile(path):
        return set(), set()
    exts, names = set(), set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            (exts if line.startswith(".") else names).add(line)
    return exts, names


MAX_TEXT_BYTES = 1_000_000     # a text file bigger than this is suspicious
ENTROPY_MIN_LEN = 64           # only score long runs
ENTROPY_THRESHOLD = 3.6        # bits/char; hex maxes at 4.0, prose ~2.5


def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
    except OSError:
        return False
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    # crude printable-ratio sniff
    printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(chunk) < 0.85


class Violation:
    def __init__(self, path, line, rule, detail):
        self.path, self.line, self.rule, self.detail = path, line, rule, detail

    def __str__(self):
        loc = f"{self.path}:{self.line}" if self.line else self.path
        return f"  {loc}\n      [{self.rule}] {self.detail}"


def check_type(path: str, rel: str, extra_ext=frozenset(),
               extra_names=frozenset()):
    """Allowlist on file type. Everything not named as text is refused."""
    base = os.path.basename(rel)
    ext = os.path.splitext(base)[1].lower()

    if ext in DENY_EXT:
        return [Violation(rel, 0, "denied-type",
                          f"{ext} = {DENY_EXT[ext]}. Rule 9: commit what you "
                          f"derived from it, never the artifact.")]
    if (base not in ALLOWED_NAMES and ext not in ALLOWED_EXT
            and base not in extra_names and ext not in extra_ext):
        return [Violation(rel, 0, "not-allowlisted",
                          f"'{ext or base}' is not an allowed text format. "
                          f"Add it to ALLOWED_EXT only if it is genuinely text.")]
    if is_binary(path):
        return [Violation(rel, 0, "binary-content",
                          "extension says text, content is binary.")]
    try:
        if os.path.getsize(path) > MAX_TEXT_BYTES:
            return [Violation(rel, 0, "oversize-text",
                              f"{os.path.getsize(path)} bytes of 'text'. "
                              f"Split it or check what it really is.")]
    except OSError:
        pass
    return []


def check_name(rel: str):
    base = os.path.basename(rel)
    ext = os.path.splitext(base)[1].lower()
    if ext in NAMEABLE_EXT:
        return []                # prose and source may be named for a subject
    m = DENY_NAME_RE.search(base)
    if m:
        return [Violation(rel, 0, "secret-filename",
                          f"filename contains '{m.group(2)}' and is not prose. "
                          f"If this is a dump, it does not belong here.")]
    return []


def check_content(path: str, rel: str):
    out = []
    ext = os.path.splitext(rel)[1].lower()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [Violation(rel, 0, "unreadable", str(exc))]

    for n, line in enumerate(lines, 1):
        if len(line) > 4096:
            out.append(Violation(rel, n, "long-line",
                                 f"{len(line)} chars -- blobs hide in long lines."))

        labelled = bool(DIGEST_CTX.search(line))

        for m in HEX_RUN.finditer(line):
            run = m.group(1)
            if labelled and len(run) in DIGEST_WIDTHS:
                continue               # a labelled digest of a standard width
            out.append(Violation(
                rel, n, "unlabelled-hex",
                f"{len(run)} hex chars ('{run[:8]}...{run[-4:]}'). "
                f"A digest must sit on a line naming it (sha256: ...); "
                f"anything else this shape is treated as key material."))

        for m in B64_RUN.finditer(line):
            run = m.group(1)
            # hex is a SUBSET of the base64 alphabet, so a labelled digest
            # lands here too. It already cleared the hex rule above; do not
            # convict it twice.
            if (labelled and len(run) in DIGEST_WIDTHS
                    and re.fullmatch(r"[0-9a-fA-F]+", run)):
                continue
            if shannon(run) >= ENTROPY_THRESHOLD:
                out.append(Violation(
                    rel, n, "base64-blob",
                    f"{len(run)} base64 chars, entropy {shannon(run):.2f}."))

        if ESCAPED_BYTES.search(line):
            out.append(Violation(rel, n, "escaped-bytes",
                                 "8+ consecutive \\xNN escapes -- that is a "
                                 "buffer of bytes embedded in source."))

        if BYTE_ARRAY.search(line):
            out.append(Violation(rel, n, "byte-array",
                                 "16+ consecutive 0xNN literals -- that is a "
                                 "buffer of bytes, not a described structure."))

        # keyword + value, on this line or the next
        w = SECRET_WORD.search(line)
        if w:
            window = line + (lines[n] if n < len(lines) else "")
            for m in re.finditer(r"[0-9a-fA-F]{16,}", window):
                if DIGEST_CTX.search(window):
                    continue
                out.append(Violation(
                    rel, n, "secret-with-value",
                    f"'{w.group(1)}' appears beside {len(m.group(0))} hex "
                    f"chars. Describe the field's offset, size and algorithm "
                    f"-- never its value."))
                break

        # a long high-entropy token of any alphabet -- prose and data only
        if ext not in ENTROPY_EXT:
            continue
        for tok in re.findall(r"\S{%d,}" % ENTROPY_MIN_LEN, line):
            if DIGEST_CTX.search(line) or "/" in tok or tok.startswith("http"):
                continue
            if not set(tok) <= BLOB_CHARS:
                continue          # contains code punctuation: not a payload
            if shannon(tok) >= ENTROPY_THRESHOLD and not HEX_RUN.search(tok):
                out.append(Violation(
                    rel, n, "high-entropy-token",
                    f"{len(tok)} chars, entropy {shannon(tok):.2f}."))
                break
    return out


def gather(args):
    if args.staged:
        r = subprocess.run(["git", "diff", "--cached", "--name-only",
                            "--diff-filter=ACM"],
                           capture_output=True, text=True)
        return [p for p in r.stdout.split("\n") if p and os.path.exists(p)]
    if args.all:
        # --cached AND --others: a brand-new, unstaged file is exactly the kind
        # most likely to be an artifact somebody dropped in the tree, so the
        # full-tree scan must see it. Plain `git ls-files` lists only TRACKED
        # files and would report a clean tree while a NOR dump sat untracked
        # beside it.
        #
        # NOT --exclude-standard: .gitignore lists precisely the artifact types
        # we care most about, so excluding ignored files would blind the scan
        # to a PUP or a NOR dump in the working tree. They are reported
        # separately by gather_ignored() as a WARNING rather than a violation,
        # because `re acquire` legitimately leaves an artifact on disk -- git
        # will not commit it, and that is the intended workflow.
        r = subprocess.run(["git", "ls-files", "--cached", "--others"],
                           capture_output=True, text=True)
        files = [p for p in r.stdout.split("\n") if p and os.path.exists(p)]
        if files:
            return files
        out = []
        for root, dirs, names in os.walk("."):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            out += [os.path.join(root, f)[2:] for f in names]
        return out
    return args.paths


def ignored_set():
    """Files git would not commit. Present in the tree, invisible to a commit."""
    r = subprocess.run(["git", "ls-files", "--others", "--ignored",
                        "--exclude-standard"], capture_output=True, text=True)
    return {p for p in r.stdout.split("\n") if p}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("paths", nargs="*")
    args = ap.parse_args()

    if not (args.staged or args.all or args.paths):
        ap.print_usage()
        return 2

    targets = gather(args)
    extra_ext, extra_names = load_local_allow()
    ignored = ignored_set() if args.all else set()
    violations, parked = [], []
    for path in targets:
        rel = os.path.relpath(path)
        if rel.startswith(".git/") or "/__pycache__/" in rel:
            continue
        # An artifact git would refuse to commit anyway: note it, do not fail.
        # `re acquire` puts real PUPs here on purpose.
        if rel in ignored:
            ext = os.path.splitext(rel)[1].lower()
            if ext in DENY_EXT:
                parked.append((rel, DENY_EXT[ext]))
            continue
        v = check_type(path, rel, extra_ext, extra_names)
        violations += v
        if v:
            continue                    # type refused; do not read content
        violations += check_name(rel)
        violations += check_content(path, rel)

    if parked and not args.quiet:
        print(f"leakcheck: {len(parked)} artifact(s) in the working tree, "
              f"gitignored so they cannot be committed:")
        for rel, why in parked:
            print(f"    {rel}  ({why})")
        print("    Fine where they are -- `re acquire` leaves them here. Do "
              "not move one into a tracked path, and publish only what you\n"
              "    derived from it (rule 9).")

    if not violations:
        if not args.quiet:
            print(f"leakcheck: {len(targets) - len(parked)} file(s) clean.")
        return 0

    print(f"\nleakcheck: {len(violations)} violation(s) in "
          f"{len(set(v.path for v in violations))} file(s).\n", file=sys.stderr)
    for v in violations:
        print(v, file=sys.stderr)
    print("\nNothing was committed. See AGENTS.md rule 9: publish what you "
          "derived from an artifact, never the artifact.\n", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
