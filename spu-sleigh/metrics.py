#!/usr/bin/env python3
"""Score a decompiled-C dump. Lower is better for everything except funcs/sigs."""
import re, sys, os, json, collections

def score(path):
    s = open(path, errors='replace').read()
    funcs = re.findall(r'/\* =+ (\S+) @ (0x[0-9a-f]+) =+ \*/', s)
    sigs  = re.findall(r'^\w[\w \*]*?\s\*?(FUN_[0-9a-f]+|VT_[0-9a-f]+)\((.*?)\)\n\{', s, re.M)
    intr  = re.findall(r'__spu_[a-z0-9_]+', s)
    return dict(
        funcs        = len(funcs),
        lines        = s.count('\n'),
        failed       = s.count('decompile FAILED'),
        intrinsics   = len(intr),
        intr_distinct= len(set(intr)),
        # unrecovered inputs: Ghidra's "in_rN" / "unaff_" / "extraout_"
        in_regs      = len(re.findall(r'\bin_r\d+\b', s)),
        unaff        = len(re.findall(r'\b(?:unaff_|extraout_)\w+', s)),
        # signatures with no parameters recovered
        void_sigs    = sum(1 for _, a in sigs if a.strip() in ('void', '')),
        sigs         = len(sigs),
        # type-inference damage
        undef8       = len(re.findall(r'\bundefined8\b', s)),
        undef16      = len(re.findall(r'\bundefined16\b', s)),
        concat       = len(re.findall(r'\bCONCAT\d+\b', s)),
        subpiece     = len(re.findall(r'\bSUB\d+\b', s)),
        floatcast    = len(re.findall(r'\((?:double|float\d*|float)\)', s)),
        badspace     = s.count('BADSPACEBASE'),
        halt         = s.count('halt_baddata') + s.count('UNIMPL'),
        top_intr     = collections.Counter(intr).most_common(8),
    )

if __name__ == '__main__':
    out = {os.path.basename(p): score(p) for p in sys.argv[1:]}
    print(json.dumps(out, indent=1))
