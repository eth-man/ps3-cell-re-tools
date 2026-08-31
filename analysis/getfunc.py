#!/usr/bin/env python3
"""getfunc.py <decomp.c> <hexaddr> [...]  -- print one decompiled function."""
import re, sys
src = open(sys.argv[1]).read()
parts = re.split(r'(/\* =+ \S+ @ 0x[0-9a-f]+ =+ \*/)', src)
idx = {}
for i in range(1, len(parts), 2):
    a = int(re.search(r'@ 0x([0-9a-f]+)', parts[i]).group(1), 16)
    idx[a] = parts[i] + parts[i+1]
for h in sys.argv[2:]:
    a = int(h, 16)
    print(idx.get(a, f'/* no function at {h} */'))
