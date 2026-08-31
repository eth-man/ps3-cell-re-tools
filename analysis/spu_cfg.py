#!/usr/bin/env python3
"""Build a crude function table + call graph from spu-elf-objdump output."""
import re,sys,collections
path=sys.argv[1]
ins=re.compile(r'^\s+([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)\s*(.*)$')
rows=[]
for ln in open(path):
    m=ins.match(ln)
    if m: rows.append((int(m.group(1),16),m.group(2),m.group(3).strip()))
addr2i={a:i for i,(a,_,_) in enumerate(rows)}
# call targets
calls=collections.defaultdict(set)   # caller_entry -> set(callee)
targets=set()
brsl=re.compile(r'^\$\d+,0x([0-9a-f]+)')
for a,op,args in rows:
    if op in ('brsl','brasl'):
        m=brsl.match(args)
        if m: targets.add(int(m.group(1),16))
# function entries = brsl targets + entry point
entries=sorted(targets)
def owner(a):
    lo,hi=0,len(entries)-1; best=None
    while lo<=hi:
        mid=(lo+hi)//2
        if entries[mid]<=a: best=entries[mid]; lo=mid+1
        else: hi=mid-1
    return best
for a,op,args in rows:
    if op in ('brsl','brasl'):
        m=brsl.match(args)
        if m:
            o=owner(a)
            if o is not None: calls[o].add(int(m.group(1),16))
callers=collections.defaultdict(set)
for c,ss in calls.items():
    for s in ss: callers[s].add(c)
if __name__=='__main__':
    q=sys.argv[2] if len(sys.argv)>2 else None
    if q:
        t=int(q,16)
        o=owner(t)
        print(f"address 0x{t:x} lies in function starting 0x{o:x}")
        print(f"  calls    : "+", ".join(f"0x{x:x}" for x in sorted(calls[o])))
        print(f"  called by: "+", ".join(f"0x{x:x}" for x in sorted(callers[o])) or "  (none)")
    else:
        print(f"functions: {len(entries)}")
