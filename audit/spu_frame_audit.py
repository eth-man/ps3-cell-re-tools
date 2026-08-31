#!/usr/bin/env python3
"""Corpus-wide hunt for the sv_iso bug class: a variable-length copy into a
stack frame that is smaller than the copy can be.

WHAT sv_iso LOOKS LIKE (notes/8x), and therefore what this looks for:

    ai   $1,$1,-320        prologue: a 320-byte frame
    ...
    ai   $3,$1,112         dst = sp + 112      <- destination is ON THE STACK
    il   $4,0x3e000        src
    ori  $5,$rN,0          len comes from a REGISTER, not an immediate
    brsl <memcpy>
    ...
    lqd  $0,336($1)        saved link register lives at sp+336
    bi   $0

  headroom = (LR slot) - (dst offset) = 336 - 112 = 224 bytes.  Any length
  above that overwrites the return address.  The real bug was hijacked at
  len=0xE4 = 228 and clean at 0xE0 = 224 -- exactly the frame arithmetic.

WHY A HEURISTIC IS THE RIGHT TOOL HERE
  Proving reachability needs dataflow the scanner does not do.  The job is to
  RANK candidates so a human looks at ten functions instead of forty thousand.
  Every hit is a lead, not a finding -- confirm with anergistic, the way sv_iso
  itself was confirmed.

Usage:
    spu_frame_audit.py <file-or-dir> [-v] [--min-headroom N] [--json out.json]
"""
import sys, os, struct, argparse, json, collections
import re

# --- the four instruction forms we need -------------------------------------
def dec(w):
    """Return (kind, fields) for the encodings this audit cares about."""
    op11 = w >> 21
    op10 = w >> 22
    op9  = w >> 23
    op8  = w >> 24
    rt   = w & 0x7f
    ra   = (w >> 7) & 0x7f
    rb   = (w >> 14) & 0x7f
    if op8 == 0x1c:                                    # ai rt,ra,i10
        i10 = (w >> 14) & 0x3ff
        if i10 & 0x200: i10 -= 0x400
        return ('ai', rt, ra, i10)
    if op8 == 0x34:                                    # lqd rt,i10(ra)
        i10 = (w >> 14) & 0x3ff
        if i10 & 0x200: i10 -= 0x400
        return ('lqd', rt, ra, i10 * 16)
    if op8 == 0x24:                                    # stqd rt,i10(ra)
        i10 = (w >> 14) & 0x3ff
        if i10 & 0x200: i10 -= 0x400
        return ('stqd', rt, ra, i10 * 16)
    if op9 == 0x66:                                    # brsl rt,i16
        i16 = (w >> 7) & 0xffff
        if i16 & 0x8000: i16 -= 0x10000
        return ('brsl', rt, i16, None)
    if op9 == 0x40 or op9 == 0x41:                     # il / ilh  (immediate)
        return ('imm', rt, None, None)
    if op10 == 0x21:                                   # ila rt,i18 (immediate)
        return ('imm', rt, None, None)
    if (w >> 28) == 0x8:                               # selb rt,ra,rb,rc -- a CLAMP
        return ('sel', rt, None, None)
    if op11 in (0x240, 0x2c0, 0x241, 0x2c1):           # cgt / clgt (register)
        return ('cmp', None, ra, (w >> 14) & 0x7f)
    if op8 in (0x4c, 0x5c, 0x4d, 0x5d, 0x4e, 0x5e):    # cgti / clgti (immediate)
        return ('cmp', None, ra, None)
    # Lane manipulation preserves provenance even when it changes the value.
    # sv_iso's length is arg3.WORD1, reached by rotating the argument quadword,
    # so a tracker that only understands shift-by-zero loses the taint and the
    # control fails.  These forms propagate the source's origin.
    if op11 in (0x1fb, 0x1fc, 0x1fd, 0x1ff) and ((w >> 14) & 0x7f) != 0:
        return ('use', rt, ra, None)                   # rotqbyi/shlqbyi/etc, nonzero
    if op11 in (0x0b4, 0x0b6, 0x1cc, 0x1cd):           # rotqby / rotqbybi (register)
        return ('use', rt, ra, None)
    if op8 in (0x14, 0x15, 0x16):                      # andi / andhi / andbi
        return ('use', rt, ra, None)
    if op11 in (0x0c1, 0x081, 0x0c8, 0x040, 0x041):    # and / a / sf / or ...
        return ('use', rt, ra, None)
    if op11 == 0x1ff and ((w >> 14) & 0x7f) == 0:      # shlqbyi rt,ra,0 -- a MOVE
        return ('ori', rt, ra, 0)                      #   (sv_iso stages its dst this way)
    if op11 == 0x1fc and ((w >> 14) & 0x7f) == 0:      # rotqbyi rt,ra,0 -- also a move
        return ('ori', rt, ra, 0)
    if op8 == 0x04:                                    # ori rt,ra,i10 (a move when i10==0)
        i10 = (w >> 14) & 0x3ff
        if i10 & 0x200: i10 -= 0x400
        return ('ori', rt, ra, i10)
    if op11 == 0x1a8:                                  # bi ra
        return ('bi', None, ra, None)
    return (None, None, None, None)

def load_spu(path):
    """Return {vaddr: word} for PT_LOAD text of an SPU ELF, or None."""
    try: d = open(path, 'rb').read()
    except Exception: return None
    if len(d) < 0x40 or d[:4] != b'\x7fELF': return None
    if d[4] != 1: return None                      # SPU images are ELF32
    if struct.unpack_from('>H', d, 18)[0] != 23: return None   # EM_SPU
    phoff = struct.unpack_from('>I', d, 0x1c)[0]
    phes  = struct.unpack_from('>H', d, 0x2a)[0]
    phn   = struct.unpack_from('>H', d, 0x2c)[0]
    words = {}
    for i in range(phn):
        o = phoff + i * phes
        if o + 32 > len(d): break
        t, off, va, pa, fsz, msz, fl, al = struct.unpack_from('>8I', d, o)
        if t != 1 or not (fl & 1): continue         # PT_LOAD, executable
        for k in range(0, fsz & ~3, 4):
            if off + k + 4 <= len(d):
                words[va + k] = struct.unpack_from('>I', d, off + k)[0]
    return words or None

def functions(addrs, ins):
    """Split into functions: an entry is the first address, every brsl target,
    and the instruction after each `bi $0`.  (notes/90: a bi-$0-only scan hides
    tail-call-terminated functions, so brsl targets are included too.)"""
    ent = {addrs[0]}
    for a in addrs:
        k, rt, i16, _ = ins[a]
        if k == 'brsl':
            ent.add((a + (i16 << 2)) & 0x3ffff)
    for i, a in enumerate(addrs):
        if ins[a][0] == 'bi' and ins[a][2] == 0:
            if i + 1 < len(addrs): ent.add(addrs[i + 1])
    return sorted(e for e in ent if e in ins)


def audit(words, min_headroom=0):
    """Per function: find the frame size and link-register slot from the
    prologue, then track registers linearly so a destination staged in a
    callee-saved register is still recognised at the call site.

    That register-staging is exactly how sv_iso hides the bug:
        ai  $82,$1,112     <- destination computed here
        ... 30+ instructions ...
        ori $3,$82,0       <- moved into the argument register only at the call
    A fixed lookback window cannot see it; this can."""
    addrs = sorted(words)
    ins = {a: dec(words[a]) for a in addrs}
    ent = functions(addrs, ins)
    bounds = {e: (ent[i + 1] if i + 1 < len(ent) else addrs[-1] + 4)
              for i, e in enumerate(ent)}
    hits = []
    for e in ent:
        end = bounds[e]
        body = [a for a in addrs if e <= a < end]
        if len(body) < 6: continue
        # prologue: `stqd $0,16($1)` saves LR at OLD sp+16; `ai $1,$1,-N` then
        # makes that NEW sp + N + 16.
        frame = None; lr_at = None; save_off = None
        for a in body[:24]:
            k, rt, ra, im = ins[a]
            if k == 'stqd' and rt == 0 and ra == 1 and im is not None and im > 0:
                save_off = im
            if k == 'ai' and rt == 1 and ra == 1 and im is not None and im < 0:
                frame = -im
                if save_off is not None: lr_at = frame + save_off
                break
        if not frame or lr_at is None: continue
        # $3..$6 hold the caller's arguments on entry.  For an isolated module
        # those are iso_module_arg0..3 -- i.e. attacker-supplied (notes/81).
        # sv_iso's bug is that arg3 reaches a stack copy unbounded; a length
        # that is merely a local is ordinary code, so only ARG-derived lengths
        # are worth a human's time.
        # $3..$6 are the caller's arguments on entry.  NOTE: requiring the
        # LENGTH to trace to one of them was tried and BROKE THE CONTROL --
        # sv_iso's length is arg3.WORD1, extracted from the argument quadword
        # by shuffle ops this tracker does not model, so the true positive was
        # lost.  Left permissive until that extraction is modelled.
        reg = {3: ('arg',), 4: ('arg',), 5: ('arg',), 6: ('arg',)}
        # sv_iso's defining property: the length is NEVER CLAMPED between its
        # origin and the copy (the DMA wrapper caps at 16384, the memcpy does
        # not).  Track which registers a compare or select has touched, and
        # only report lengths that were never bounds-checked.
        clamped = set()
        for a in body:
            k, rt, ra, im = ins[a]
            if k == 'ai' and ra == 1 and rt not in (0, 1) and im is not None and im >= 0:
                reg[rt] = ('stack', im)
            elif k == 'ai' and rt not in (0, 1):
                reg[rt] = reg.get(ra, ('mem',))
            elif k == 'ori' and im == 0 and rt not in (0, 1):
                reg[rt] = reg.get(ra, ('mem',))       # register move
            elif k == 'imm':
                reg[rt] = ('imm',)
            elif k == 'cmp':
                clamped.add(ra)
                if im is not None: clamped.add(im)
            elif k == 'sel' and rt is not None:
                clamped.add(rt)
            elif k == 'use' and rt not in (0, 1):
                src = reg.get(ra)
                reg[rt] = src if src and src[0] == 'arg' else ('mem',)
                if ra in clamped: clamped.add(rt)
                else: clamped.discard(rt)
            elif k == 'lqd' and rt not in (0, 1):
                reg[rt] = ('mem',)
            elif k == 'brsl':
                d, ln = reg.get(3), reg.get(5)
                if (d and d[0] == 'stack' and ln is not None and ln[0] == 'arg'
                        and 5 not in clamped):
                    head = lr_at - d[1]
                    if 0 <= head and head >= min_headroom:
                        hits.append(dict(func=e, site=a,
                                         target=(a + (i16_of(ins[a])) * 4) & 0x3ffff,
                                         dst_off=d[1], lr_slot=lr_at, frame=frame,
                                         headroom=head, len_src=ln[0]))
                # a call clobbers the volatile registers
                for r in list(reg):
                    if r < 80: reg.pop(r, None)
    return hits


def i16_of(t):
    return t[2]


WRITES_RT = ('ai', 'lqd', 'imm', 'sel', 'use', 'ori')

def arg_defined(ins, addrs_before, reg=5, window=12):
    """Is $reg actually DEFINED as an argument in the instructions before a call?

    Works on decoded instructions, so it needs no external disassembly.
    `stqd` is excluded deliberately: it READS rt and writes memory, so counting
    it as a definition is the same mistake as assuming r5=len everywhere.
    """
    for a in reversed(addrs_before[-window:]):
        k, rt, ra, i = ins.get(a, (None, None, None, None))
        if k in WRITES_RT and rt == reg:
            return k
    return None


def callee_loops_on(words, target, reg=5, span=0x400):
    """Does the callee contain a LOOP, and does it read $reg?

    A bulk copy of a variable length must loop (or be a fixed-size sequence,
    which by definition is not variable).  me_iso 0x7040 matched every frame
    heuristic -- stack destination, source in the input region, $5 tracking the
    caller's argument -- and still wrote exactly 4 bytes at any length, because
    it has no backward branch at all.  Requiring a loop is what separates a
    copier from a validator.

    Returns (has_loop, reads_reg).
    """
    BR = {0x32: 'br', 0x21: 'brnz', 0x20: 'brz', 0x22: 'brhz', 0x23: 'brhnz'}
    has_loop = False
    reads = False
    for a in range(target, target + span, 4):
        w = words.get(a)
        if w is None:
            continue
        op8 = w >> 24
        if op8 in BR:
            i16 = (w >> 7) & 0xffff
            if i16 & 0x8000:
                i16 -= 0x10000
            if i16 < 0:                      # a backward branch = a loop
                has_loop = True
        k = dec(w)
        # $reg read as a source operand
        if k[0] in ('lqd', 'stqd', 'ai', 'use', 'ori') and k[2] == reg:
            reads = True
        if k[0] == 'cmp' and (k[2] == reg or k[3] == reg):
            reads = True
        if k[0] == 'bi' and a > target + 8:
            break
    return has_loop, reads


def callee_uses_reg_as(ins, addrs, target, reg=5, window=40):
    """Does the CALLEE treat $reg as a COUNT or as a POINTER?

    Frame arithmetic alone cannot tell memcpy(dst,src,len) from any other
    three-argument call -- which is why the first corpus run produced ~97k
    hits.  Look at the callee:
        lqd/stqd based on $reg      -> pointer, NOT a length
        compared, or added into     -> genuine count
    """
    body = [a for a in addrs if target <= a < target + window * 4]
    for a in body:
        k, rt, ra, i = ins.get(a, (None, None, None, None))
        if k in ('lqd', 'stqd') and ra == reg:
            return 'pointer'
    for a in body:
        k, rt, ra, i = ins.get(a, (None, None, None, None))
        if k == 'cmp' and (ra == reg or i == reg):
            return 'count'
        if k == 'ai' and ra == reg:
            return 'count'
    return 'unknown'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path'); ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--min-headroom', type=int, default=0)
    ap.add_argument('--json')
    a = ap.parse_args()
    files = []
    if os.path.isdir(a.path):
        for r, _, fs in os.walk(a.path):
            for f in fs:
                if f.endswith(('.elf', '.self')): files.append(os.path.join(r, f))
    else:
        files = [a.path]
    import hashlib
    scanned = 0; out = []; seen_hash = {}
    for f in files:
        try: hh = hashlib.sha1(open(f,'rb').read()).hexdigest()
        except Exception: continue
        if hh in seen_hash: continue          # the corpus stores duplicates under hash names
        seen_hash[hh] = f
        w = load_spu(f)
        if not w: continue
        scanned += 1
        addrs = sorted(w); ins = {x: dec(w[x]) for x in addrs}
        for h in audit(w, a.min_headroom):
            before = [x for x in addrs if x < h['site']]
            d = arg_defined(ins, before)
            if not d:
                h['drop'] = 'stale-$5'
            elif d == 'imm':
                h['drop'] = 'constant-length'
            else:
                u = callee_uses_reg_as(ins, addrs, h['target'])
                h['drop'] = None if u != 'pointer' else 'callee-derefs-$5'
                h['callee'] = u
            h['len_set_by'] = d
            h['file'] = f; out.append(h)
    raw = len(out)
    from collections import Counter
    reasons = Counter(h.get('drop') for h in out if h.get('drop'))
    out = [h for h in out if not h.get('drop')]
    out.sort(key=lambda h: h['headroom'])
    print("scanned %d SPU images (of %d files)" % (scanned, len(files)))
    print("  raw frame-arithmetic hits      %d" % raw)
    for r, n in reasons.most_common():
        print("  dropped: %-22s %d" % (r, n))
    print("  SURVIVING candidates           %d" % len(out))
    print("%-52s %8s %8s %8s %9s" % ("file", "site", "dst=sp+", "LR@sp+", "headroom"))
    for h in out[:40]:
        print("%-52s %8x %8d %8d %9d"
              % (os.path.basename(h['file'])[:52], h['site'], h['dst_off'],
                 h['lr_slot'], h['headroom']))
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1)
        print("wrote", a.json)

def classify_callee(insns, idx_by_addr, target, window=40):
    """Does the CALLEE actually treat $5 as a count, or as a pointer?

    The frame-arithmetic pattern alone cannot tell a memcpy(dst,src,len) from
    any other 3-argument call.  Matching on the call site is what produced ~97k
    corpus-wide hits: most are calls whose third argument is another pointer, or
    whose callee takes fewer arguments so $5 is simply stale.  Look at what the
    callee does with $5 instead:

        dereferenced (lqd/lqx/stqd/stqx based on $5)  -> pointer, NOT a length
        compared or added into a bound                -> genuine count
        neither, within `window`                      -> unknown, needs a look

    Returns 'pointer' | 'count' | 'unknown'.
    """
    i = idx_by_addr.get(target)
    if i is None:
        return 'unknown'
    body = "\n".join(insns[i:i + window])
    if re.search(r'\b(lq[dx]|stq[dx])\s+\$\d+,[^\n]*\$5\b', body) or re.search(r'\$5\)', body):
        return 'pointer'
    if re.search(r'\b(cgti|clgti|ceq|cgt|clgt|ai|a)\s+\$\d+,\$5\b', body):
        return 'count'
    return 'unknown'


def arg_is_live(insns, site_idx, reg=5, window=12):
    """Is $reg actually SET as an argument before this brsl?

    The original heuristic assumed the SPU ABI r3/r4/r5 = dst/src/len at every
    call site.  That is wrong wherever the callee takes fewer arguments: $5 then
    holds a stale value (often a stack pointer), which reads as a gigantic
    "length" and manufactures an overflow that does not exist.  Three of the ten
    tightest appldr hits were exactly this.  Requiring the register to be
    written in the window before the call removes them.
    """
    for k in range(max(0, site_idx - window), site_idx):
        t = insns[k]
        m = re.match(r'\s*[0-9a-f]+:\s+(?:[0-9a-f]{2} ){4}\s*(\w+)\s+\$(\d+)', t)
        if m and int(m.group(2)) == reg:
            # STORES read their first operand, they do not define it.  Counting
            # `stqd $5,..` as "sets $5" is the same class of error as assuming
            # r5=len at every call site.
            if m.group(1) in ('stqd', 'stqx', 'stqa', 'stqr'):
                continue
            return True, m.group(1)
    return False, None


if __name__ == '__main__':
    main()
