#!/usr/bin/env python3
"""Sound-ish SPU function boundaries + call graph. USE THIS, not a bi $0 scan.

Two heuristics failed badly in notes/90 and each produced WRONG conclusions:

  bi $0 only        394 "functions" -- misses every TAIL-CALL-terminated function,
                    so its successor's entry is swallowed. This hid 0x16ef0 and
                    made `0x15d60 -> inflateInit_` come back False. It also hid
                    0x181d8 behind alignment padding earlier in the same note.
  + every br target 1132 "functions" -- `br` is ALSO an ordinary intra-function
                    jump, so basic blocks become fake functions and callers move
                    (0x15d60's caller became 0x167c4, a block inside 0x166d0).

Entries here = first instruction
             + every `brsl` target                 (anything called is a function)
             + the instruction after every `bi $0`
             + every vtable slot value             (dispatch-only entries such as
                                                    0x16ef0 are reached no other way)

Only inter-function edges are kept (a br/brsl whose target is itself an entry).
Gives 453 functions on appldr 4.93 and reproduces every hand-verified fact.
"""
import re, struct, collections, sys

def load(asm, elf, vt_lo=0x34000, vt_hi=0x34400, delta=0x12b00,
         code_lo=0x12c00, code_hi=0x37250):
    b = open(elf,'rb').read()
    ins=[]
    for l in open(asm):
        m=re.match(r'\s*([0-9a-f]+):\s+(?:[0-9a-f]{2} ){4}\s*(\S+)(.*)', l)
        if m: ins.append((int(m.group(1),16), m.group(2), m.group(3).strip().split('\t')[0]))
    addrs={a for a,_,_ in ins}
    ent={ins[0][0]}
    for a,op,ops in ins:
        if op=='brsl':
            m=re.search(r'0x([0-9a-f]+)$',ops)
            if m: ent.add(int(m.group(1),16))
    for i,(a,op,ops) in enumerate(ins):
        if op=='bi' and ops=='$0':
            j=i+1
            while j<len(ins) and ins[j][1]=='lnop': j+=1
            if j<len(ins): ent.add(ins[j][0])
    for ls in range(vt_lo, vt_hi, 4):
        try: v=struct.unpack('>I', b[ls-delta:ls-delta+4])[0]
        except Exception: continue
        if v in addrs and code_lo<=v<code_hi: ent.add(v)
    ent=sorted(ent)
    def fn_of(a):
        r=ent[0]
        for e in ent:
            if e<=a: r=e
            else: break
        return r
    calls=collections.defaultdict(set)
    for a,op,ops in ins:
        if op in ('brsl','br'):
            m=re.search(r'0x([0-9a-f]+)$',ops)
            if m:
                t=int(m.group(1),16)
                if fn_of(t)==t: calls[fn_of(a)].add(t)
    return ins, ent, fn_of, calls

def reach(calls, s, t, seen=None):
    if seen is None: seen=set()
    if s in seen: return False
    seen.add(s)
    for n in calls.get(s,()):
        if n==t or reach(calls,n,t,seen): return True
    return False

if __name__ == '__main__':
    ins,ent,fn_of,calls = load('disasm/appldr-493.asm',
                               'extracted/loaders-493/appldr-493.elf')
    print(f"{len(ent)} functions, {sum(len(v) for v in calls.values())} edges")
