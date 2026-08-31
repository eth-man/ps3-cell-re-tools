#!/usr/bin/env python3
"""Mechanically name functions in lv1's userland binaries.

Every method logs "In <class>::<method>: ", so a function that loads a pointer to
such a string is (almost always) that method.  This is falsifiable: a function
either claims its own name or stays unnamed.  No proximity guessing.

Usage: ss_symmap.py <prog.elf> <prog.asm>
"""
import re, struct, sys, collections

def segs(d):
    phoff=struct.unpack('>Q',d[0x20:0x28])[0]
    phes=struct.unpack('>H',d[0x36:0x38])[0]; phn=struct.unpack('>H',d[0x38:0x3a])[0]
    out=[]
    for i in range(phn):
        o=phoff+i*phes
        if struct.unpack('>I',d[o:o+4])[0]!=1: continue
        off,va,pa,fsz,msz=struct.unpack('>QQQQQ',d[o+8:o+48])
        out.append((va,off,fsz))
    return out

def solve_r2(d,S):
    """largest contiguous run of pointers in the LAST load segment, + 0x8000"""
    va0,off0,fsz=S[-1]
    def isptr(q): return any(v<=q<v+f for v,o,f in S)
    best=(0,0,0); cur=None
    for i in range(0,fsz-8,8):
        q=struct.unpack('>Q',d[off0+i:off0+i+8])[0]
        if isptr(q):
            if cur is None: cur=[i,i]
            else: cur[1]=i
        else:
            if cur and cur[1]-cur[0]>best[1]-best[0]: best=(cur[0],cur[1],0)
            cur=None
    if cur and cur[1]-cur[0]>best[1]-best[0]: best=(cur[0],cur[1],0)
    return va0+best[0]+0x8000

def main(elf,asm,r2_override=None):
    d=open(elf,'rb').read(); S=segs(d)
    r2=r2_override if r2_override else solve_r2(d,S)
    def va2off(va):
        for v,o,f in S:
            if v<=va<v+f: return o+(va-v)
        return None
    # 1+2. INVERTED: walk every pointer-shaped word; read the C string at its
    # target.  This catches SUFFIX pointers ("ity_policy_manager::request: ")
    # that a regex-first pass would miss entirely.
    def cstr(va,maxlen=96):
        """Return the CONTAINING string: TOC slots point at shared SUFFIXES
        (compiler string-tail merging), so reading forward from the pointer
        loses the class::method prefix.  Walk back to the previous NUL."""
        o=va2off(va)
        if o is None: return None
        s0=o
        while s0>0 and d[s0-1]!=0 and o-s0<160: s0-=1
        if s0!=o: return None   # SUFFIX pointer (string-tail merging): the
                                # function is printing a shared tail, NOT
                                # announcing itself.  This is what mislabelled
                                # 0x8000dcc4 as ::request (pointer was +8 in).
        b=d[s0:s0+200]
        z=b.find(b'\x00')
        if z>=0: b=b[:z]
        if not b or not all(32<=c<127 for c in b): return None
        return b.decode()
    disp={}
    for v,o,f in S:
        for i in range(0,f-8,8):
            q=struct.unpack('>Q',d[o+i:o+i+8])[0]
            if not any(vv<=q<vv+ff for vv,oo,ff in S): continue
            t=cstr(q)
            if not t or '::' not in t: continue
            dd=(v+i)-r2
            if -32768<=dd<=32767: disp[dd]=t
    # 3. bind displacements to the enclosing function
    lines=open(asm).read().splitlines()
    addr=re.compile(r'^\s*([0-9a-fA-F]+):')
    # ONLY r5: this binary's logger ABI is (r3=handle, r4=level, r5=format,
    # r6..=varargs).  A vtable / debug-name pointer is loaded into r0/r9 and
    # STORED into an object -- binding on any register named a CONSTRUCTOR
    # (0x8000115c) as `get_object_entry`.  r5 is the format-string slot.
    ldr =re.compile(r'ld\s+r5,(-?\d+)\(r2\)')
    # BOUNDARY FIX: a function ENDS at `blr`; the next instruction starts a new
    # one.  Keying on `stdu r1,-` merged every LEAF function into its predecessor
    # and credited that predecessor with the leaf's strings (this mislabelled
    # 0x8000115c, a constructor, as object_hashtable::get_object_entry).
    starts=[]; new_next=True
    for l in lines:
        a=addr.search(l)
        if not a: continue
        va=int(a.group(1),16)
        if new_next:
            starts.append(va); new_next=False
        if re.search(r'\bblr\b',l): new_next=True
    starts=sorted(set(starts))
    import bisect
    def fn_of(va):
        i=bisect.bisect_right(starts,va)-1
        return starts[i] if i>=0 else None
    hits=collections.defaultdict(set)
    for l in lines:
        a=addr.search(l); m=ldr.search(l)
        if not (a and m): continue
        dd=int(m.group(1))
        if dd in disp:
            f=fn_of(int(a.group(1),16))
            if f is not None: hits[f].add(disp[dd])
    print("r2 = 0x%08x    %d TOC displacements to '::' strings, %d functions named"
          %(r2,len(disp),len(hits)))
    return r2,hits

if __name__=='__main__':
    ov=int(sys.argv[3],16) if len(sys.argv)>3 else None
    r2,hits=main(sys.argv[1],sys.argv[2],ov)
    def rank(n):
        # a function's own announcement is "In <class>::<method>: " -- prefer it,
        # then the longest full class::method, then anything.
        full = n.startswith('In ') and '::' in n
        return (0 if full else 1, -len(n))
    named=0
    for va in sorted(hits):
        names=sorted(hits[va],key=rank)
        best=names[0]
        conf = "OWN-LOG " if best.startswith('In ') else "fragment"
        if best.startswith('In '): named+=1
        print("  0x%08x  [%s] %-52s %s"%(va,conf,best,
              ("(+%d other)"%(len(names)-1)) if len(names)>1 else ""))
    print("\n  %d/%d functions carry their OWN 'In class::method' announcement"%(named,len(hits)))
