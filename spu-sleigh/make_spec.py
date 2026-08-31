#!/usr/bin/env python3
"""Generate work/spu.{sinc,cspec} from baseline/ .

The upstream GhidraSPU spec models the SPU as a scalar 64-bit machine. This
rebuilds it as what the hardware is: 128 registers of 128 bits, operated on in
lanes, with every scalar living in the *preferred slot* (quadword bytes 0..3,
which in a big-endian register space is the most significant 4 bytes).

Bit ranges, counting from the LSB of a 16-byte register:
    word lane w (0..3)     -> [ (3-w)*32, 32 ]   ; lane 0 = [96,32] = preferred
    halfword lane h (0..7) -> [ (7-h)*16, 16 ]
    byte lane b (0..15)    -> [ (15-b)*8, 8 ]

Only constructor *bodies* are rewritten; every decode pattern stays verbatim.
"""
import re, sys, os

W = [96, 64, 32, 0]                      # word lanes, MSB-first
H = [(7-h)*16 for h in range(8)]         # halfword lanes
B = [(15-b)*8 for b in range(16)]        # byte lanes

def lanes(n):
    return {4: W, 8: H, 16: B}[n]

# ---------------------------------------------------------------- helpers --
def lanewise(nlanes, width, expr, rt='RR_RT', srcs=('RR_RA','RR_RB')):
    """expr is a format string over a{lane}/b{lane} placeholders."""
    sz = width // 8
    out = ['    local t:16 = 0;']
    for i, off in enumerate(lanes(nlanes)):
        d = {}
        for j, s in enumerate(srcs):
            d['ab'[j]] = f'{s}[{off},{width}]'
        out.append(f'    t[{off},{width}] = {expr.format(**d)};')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

def cmp_body(nlanes, width, op, rt, a, b):
    """per-lane compare -> all-ones / all-zeros, branchless."""
    out = ['    local t:16 = 0;']
    for off in lanes(nlanes):
        out.append(f'    t[{off},{width}] = -zext({a}[{off},{width}] {op} {b});'
                   if b.startswith(('0x', '-')) or b.lstrip('-').isdigit()
                   else f'    t[{off},{width}] = -zext({a}[{off},{width}] {op} {b}[{off},{width}]);')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

def imm_repl(rt, width, expr):
    """replicate an immediate into every lane of `width` bits."""
    n = {32: 4, 16: 8, 8: 16}[width]
    out = ['    local t:16 = 0;']
    for off in lanes(n):
        out.append(f'    t[{off},{width}] = {expr};')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

IDENT = ('    local t:16 = 0;\n'
         '    t[64,64] = 0x1011121314151617;\n'
         '    t[0,64]  = 0x18191A1B1C1D1E1F;')

def ctrl(rt, addr, align, width_bytes, sel_hi, sel_lo=None):
    """Generate-controls-for-insertion (cbd/chd/cwd/cdd and the x-forms).

    Base pattern selects all of B (0x10..0x1F); the field at byte index i is
    overwritten with the bytes that select the corresponding slice of A."""
    nb = width_bytes
    body = [f'    local i:4 = ({addr}) & 0x{align:X};',
            f'    local sh:4 = ({16 - nb} - i) * 8;',
            IDENT,
            f'    local m:16 = zext(0x{(1 << (8*nb)) - 1:X}:{nb}) << sh;']
    if nb <= 8:
        body.append(f'    local v:16 = zext(0x{sel_hi:0{2*nb}X}:{nb}) << sh;')
    body += [f'    {rt} = (t & ~m) | v;']
    return '\n'.join(body)

def select_mask(rt, src, nbits, unit_bits, immediate=False):
    """fsm/fsmh/fsmb(i): bit i of the mask selects all-ones or all-zeros for unit i."""
    ub = unit_bits // 8
    out = ['    local t:16 = 0;']
    for i in range(nbits):
        off = (nbits - 1 - i) * unit_bits
        k = nbits - 1 - i
        if True:
            out.append(f'    local v{i}:4 = (({src}) >> {k}) & 1;')
            if ub == 4:
                out.append(f'    t[{off},{unit_bits}] = -v{i};')
            else:
                out.append(f'    local b{i}:{ub} = v{i}:{ub};')
                out.append(f'    t[{off},{unit_bits}] = -b{i};')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

def gather(rt, src, nunits, unit_bits):
    """gb/gbh/gbb: LSB of each unit -> packed into the preferred slot."""
    out = ['    local g:4 = 0;']
    for i in range(nunits):
        off = (nunits - 1 - i) * unit_bits
        out.append(f'    g = g | (zext({src}[{off},1]) << {nunits - 1 - i});')
    out += ['    local t:16 = 0;', '    t[96,32] = g;', f'    {rt} = t;']
    return '\n'.join(out)

# ================================================================= bodies ==
def W4(expr, rt='RR_RT', srcs=('RR_RA','RR_RB')): return lanewise(4, 32, expr, rt, srcs)
def H8(expr, rt='RR_RT', srcs=('RR_RA','RR_RB')): return lanewise(8, 16, expr, rt, srcs)
def B16(expr, rt='RR_RT', srcs=('RR_RA','RR_RB')): return lanewise(16, 8, expr, rt, srcs)

BODIES = {}

# ---- memory: full quadword, address from the preferred slot, 16B aligned --
BODIES['lqx']  = ('    local ea:4 = (RR_RA[96,32] + RR_RB[96,32]) & 0xFFFFFFF0;\n'
                  '    RR_RT = *[ram]:16 ea;')
BODIES['stqx'] = ('    local ea:4 = (RR_RA[96,32] + RR_RB[96,32]) & 0xFFFFFFF0;\n'
                  '    *[ram]:16 ea = RR_RT;')
BODIES['lqa']  = '    RI16_RT = *[ram]:16 LSAabsolute;'
BODIES['stqa'] = '    *[ram]:16 LSAabsolute = RI16_RT;'
BODIES['lqr']  = ('    local ea:4 = (inst_start + (RI16_I16 << 2)) & 0x3FFF0;\n'
                  '    RI16_RT = *[ram]:16 ea;')
BODIES['stqr'] = ('    local ea:4 = (inst_start + (RI16_I16 << 2)) & 0x3FFF0;\n'
                  '    *[ram]:16 ea = RI16_RT;')

# ---- immediates: replicated across lanes, as the hardware does ------------
BODIES['il']   = imm_repl('RI16_RT', 32, 'RI16_I16')
BODIES['ilh']  = imm_repl('RI16_RT', 16, 'RI16_I16:2')
BODIES['ilhu'] = imm_repl('RI16_RT', 32, '(RI16_I16 << 16)')
BODIES['ila']  = imm_repl('RI18_RT', 32, 'RI18_I18u')
BODIES['iohl'] = W4('{a} | (0x{i:X}:4)'.format(a='{a}', i=0), 'RI16_RT', ('RI16_RT',))
BODIES['iohl'] = '\n'.join(
    ['    local t:16 = RI16_RT;'] +
    [f'    t[{o},32] = RI16_RT[{o},32] | (RI16_I16 & 0xFFFF);' for o in W] +
    ['    RI16_RT = t;'])

# ---- word / halfword arithmetic -----------------------------------------
BODIES['a']    = W4('{a} + {b}')
BODIES['ai']   = W4('{a} + RI10_I10', 'RI10_RT', ('RI10_RA',))
BODIES['sf']   = W4('{b} - {a}')
BODIES['sfi']  = W4('RI10_I10 - {a}', 'RI10_RT', ('RI10_RA',))
BODIES['ah']   = H8('{a} + {b}')
BODIES['ahi']  = H8('{a} + RI10_I10:2', 'RI10_RT', ('RI10_RA',))
BODIES['sfh']  = H8('{b} - {a}')
BODIES['sfhi'] = H8('RI10_I10:2 - {a}', 'RI10_RT', ('RI10_RA',))
BODIES['addx'] = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},32] = RR_RA[{o},32] + RR_RB[{o},32] + (RR_RT[{o},32] & 1);' for o in W] +
    ['    RR_RT = t;'])
BODIES['sfx']  = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},32] = RR_RB[{o},32] - RR_RA[{o},32] - (1 - (RR_RT[{o},32] & 1));' for o in W] +
    ['    RR_RT = t;'])
def carry_body(a_expr, plus_one=False, use_rt_carry=False, negate_a=False, rt='RR_RT'):
    out = ['    local t:16 = 0;']
    for i, o in enumerate(W):
        out.append(f'    local a{i}:4 = ' + ('~' if negate_a else '') + f'RR_RA[{o},32];')
        out.append(f'    local x{i}:8 = zext(a{i});')
        out.append(f'    local y{i}:8 = zext(RR_RB[{o},32]);')
        if use_rt_carry:
            out.append(f'    local c{i}:4 = RR_RT[{o},32] & 1;')
            out.append(f'    local z{i}:8 = zext(c{i});')
            sum_ = f'x{i} + y{i} + z{i}'
        elif plus_one:
            sum_ = f'x{i} + y{i} + 1'
        else:
            sum_ = f'x{i} + y{i}'
        out.append(f'    t[{o},32] = zext(({sum_}) > 0xFFFFFFFF);')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

BODIES['cg']  = carry_body(None)
BODIES['cgx'] = carry_body(None, use_rt_carry=True)
BODIES['bg']  = carry_body(None, plus_one=True, negate_a=True)
BODIES['bgx'] = carry_body(None, use_rt_carry=True, negate_a=True)
# ---- sign extension ------------------------------------------------------
BODIES['xsbh'] = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},16] = sext(RR_RA[{o},8]);' for o in H] + ['    RR_RT = t;'])
BODIES['xshw'] = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},32] = sext(RR_RA[{o},16]);' for o in W] + ['    RR_RT = t;'])
BODIES['xswd'] = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},64] = sext(RR_RA[{o},32]);' for o in (64, 0)] + ['    RR_RT = t;'])

# ---- immediate logicals: the immediate is replicated per lane ------------
BODIES['andbi'] = B16('{a} & (RI10_I10 & 0xFF)', 'RI10_RT', ('RI10_RA',))
BODIES['andhi'] = H8('{a} & RI10_I10:2',         'RI10_RT', ('RI10_RA',))
BODIES['andi']  = W4('{a} & RI10_I10',           'RI10_RT', ('RI10_RA',))
BODIES['orbi']  = B16('{a} | (RI10_I10 & 0xFF)', 'RI10_RT', ('RI10_RA',))
BODIES['orhi']  = H8('{a} | RI10_I10:2',         'RI10_RT', ('RI10_RA',))
BODIES['ori']   = W4('{a} | RI10_I10',           'RI10_RT', ('RI10_RA',))
BODIES['xorbi'] = B16('{a} ^ (RI10_I10 & 0xFF)', 'RI10_RT', ('RI10_RA',))
BODIES['xorhi'] = H8('{a} ^ RI10_I10:2',         'RI10_RT', ('RI10_RA',))
BODIES['xori']  = W4('{a} ^ RI10_I10',           'RI10_RT', ('RI10_RA',))
BODIES['orx']   = ('    local g:4 = RR_RA[96,32] | RR_RA[64,32] | RR_RA[32,32] | RR_RA[0,32];\n'
                   '    local t:16 = 0;\n    t[96,32] = g;\n    RR_RT = t;')

# ---- compares: per lane, all-ones or all-zeros ---------------------------
for mn, (n, w, op, rt, a, b) in {
    'ceqb' :(16,8, '==','RR_RT','RR_RA','RR_RB'), 'ceqh' :(8,16,'==','RR_RT','RR_RA','RR_RB'),
    'ceq'  :(4,32, '==','RR_RT','RR_RA','RR_RB'), 'cgtb' :(16,8, 's>','RR_RT','RR_RA','RR_RB'),
    'cgth' :(8,16, 's>','RR_RT','RR_RA','RR_RB'), 'cgt'  :(4,32, 's>','RR_RT','RR_RA','RR_RB'),
    'clgtb':(16,8, '>', 'RR_RT','RR_RA','RR_RB'), 'clgth':(8,16, '>', 'RR_RT','RR_RA','RR_RB'),
    'clgt' :(4,32, '>', 'RR_RT','RR_RA','RR_RB'),
}.items():
    BODIES[mn] = cmp_body(n, w, op, rt, a, b)
for mn, (n, w, op, imm) in {
    'ceqbi' :(16,8, '==','RI10_I10 & 0xFF'), 'ceqhi' :(8,16,'==','RI10_I10 & 0xFFFF'),
    'ceqi'  :(4,32, '==','RI10_I10'),          'cgtbi' :(16,8, 's>','RI10_I10 & 0xFF'),
    'cgthi' :(8,16, 's>','RI10_I10 & 0xFFFF'),        'cgti'  :(4,32, 's>','RI10_I10'),
    'clgtbi':(16,8, '>', 'RI10_I10 & 0xFF'), 'clgthi':(8,16, '>', 'RI10_I10 & 0xFFFF'),
    'clgti' :(4,32, '>', 'RI10_I10'),
}.items():
    wb = w // 8
    lines_ = ['    local t:16 = 0;', f'    local iw:4 = {imm};']
    if wb != 4:
        lines_.append(f'    local ic:{wb} = iw:{wb};')
        rhs = 'ic'
    else:
        rhs = 'iw'
    lines_ += [f'    t[{o},{w}] = -zext(RI10_RA[{o},{w}] {op} {rhs});' for o in lanes(n)]
    lines_.append('    RI10_RT = t;')
    BODIES[mn] = '\n'.join(lines_)

# ---- shifts and rotates, per lane ---------------------------------------
BODIES['shl']    = W4('{a} << ({b} & 0x3F)')
BODIES['shli']   = W4('{a} << (RI7_I7 & 0x3F)', 'RI7_RT', ('RI7_RA',))
BODIES['shlh']   = H8('{a} << ({b} & 0x1F)')
BODIES['shlhi']  = H8('{a} << (RI7_I7 & 0x1F)', 'RI7_RT', ('RI7_RA',))
BODIES['rot']    = W4('({a} << ({b} & 0x1F)) | ({a} >> (32 - ({b} & 0x1F)))')
BODIES['roti']   = W4(f'({{a}} << (RI7_I7 & 0x1F)) | ({{a}} >> (32 - (RI7_I7 & 0x1F)))',
                      'RI7_RT', ('RI7_RA',))
BODIES['roth']   = H8('({a} << ({b} & 0xF)) | ({a} >> (16 - ({b} & 0xF)))')
BODIES['rothi']  = H8('({a} << (RI7_I7 & 0xF)) | ({a} >> (16 - (RI7_I7 & 0xF)))',
                      'RI7_RT', ('RI7_RA',))
BODIES['rotm']   = W4('{a} >> ((0 - {b}) & 0x3F)')
BODIES['rotmi']  = W4('{a} >> ((0 - RI7_I7) & 0x3F)', 'RI7_RT', ('RI7_RA',))
BODIES['rothm']  = H8('{a} >> ((0 - {b}) & 0x1F)')
BODIES['rothmi'] = H8('{a} >> ((0 - RI7_I7) & 0x1F)', 'RI7_RT', ('RI7_RA',))
BODIES['rotma']  = W4('{a} s>> ((0 - {b}) & 0x3F)')
BODIES['rotmai'] = W4('{a} s>> ((0 - RI7_I7) & 0x3F)', 'RI7_RT', ('RI7_RA',))
BODIES['rotmah'] = H8('{a} s>> ((0 - {b}) & 0x1F)')
BODIES['rotmahi']= H8('{a} s>> ((0 - RI7_I7) & 0x1F)', 'RI7_RT', ('RI7_RA',))

# ---- whole-quadword shifts and rotates: exact, now that RT is 128 bits ---
def q(kind, mask, scale=1, byshift3=False, negate=False):
    """Whole-quadword shift/rotate. Operand field names are taken from the
    constructor header at splice time -- this spec is not consistent about
    which instructions use the RR or RI7 encoding."""
    def build(head):
        f = re.findall(r'\b(RR_RT|RR_RA|RR_RB|RI7_RT|RI7_RA|RI7_I7)\b', head.split(' is ')[0])
        rt = next(x for x in f if x.endswith('_RT'))
        ra = next(x for x in f if x.endswith('_RA'))
        src = next((x for x in f if x.endswith('_RB')), None)
        amt = f'{src}[96,32]' if src else 'RI7_I7'
        if byshift3:
            amt = f'({amt} >> 3)'
        if negate:
            amt = f'(0 - {amt})'
        amt = f'({amt} & 0x{mask:X})'
        if scale != 1:
            amt = f'{amt} * {scale}'
        if kind == 'shl':   e = f'{ra} << s'
        elif kind == 'shr': e = f'{ra} >> s'
        else:               e = f'({ra} << s) | ({ra} >> (128 - s))'
        return f'    local s:4 = {amt};\n    {rt} = {e};'
    return build

BODIES['shlqbi']    = q('shl', 0x7)
BODIES['shlqbii']   = q('shl', 0x7)
BODIES['shlqby']    = q('shl', 0x1F, 8)
BODIES['shlqbyi']   = q('shl', 0x1F, 8)
BODIES['shlqbybi']  = q('shl', 0x1F, 8, byshift3=True)
BODIES['rotqbi']    = q('rot', 0x7)
BODIES['rotqbii']   = q('rot', 0x7)
BODIES['rotqby']    = q('rot', 0xF, 8)
BODIES['rotqbyi']   = q('rot', 0xF, 8)
BODIES['rotqbybi']  = q('rot', 0xF, 8, byshift3=True)
BODIES['rotqmbi']   = q('shr', 0x7, 1, negate=True)
BODIES['rotqmbii']  = q('shr', 0x7, 1, negate=True)
BODIES['rotqmby']   = q('shr', 0x1F, 8, negate=True)
BODIES['rotqmbyi']  = q('shr', 0x1F, 8, negate=True)
BODIES['rotqmbybi'] = q('shr', 0x1F, 8, byshift3=True, negate=True)

# ---- THE POINT OF ALL THIS: generate-controls-for-insertion --------------
# These produce the shufb control masks. 25% of every shufb in metldr gets its
# mask from one of these, and the mask depends on a *runtime* address -- which
# is why resolving constants out of .rodata could never have covered them.
BODIES['cbd'] = ctrl('RI7_RT', 'RI7_RA[96,32] + RI7_I7', 0xF, 1, 0x03)
BODIES['chd'] = ctrl('RI7_RT', 'RI7_RA[96,32] + RI7_I7', 0xE, 2, 0x0203)
BODIES['cwd'] = ctrl('RI7_RT', 'RI7_RA[96,32] + RI7_I7', 0xC, 4, 0x00010203)
BODIES['cdd'] = ctrl('RI7_RT', 'RI7_RA[96,32] + RI7_I7', 0x8, 8, 0x0001020304050607)
BODIES['cbx'] = ctrl('RR_RT', 'RR_RA[96,32] + RR_RB[96,32]', 0xF, 1, 0x03)
BODIES['chx'] = ctrl('RR_RT', 'RR_RA[96,32] + RR_RB[96,32]', 0xE, 2, 0x0203)
BODIES['cwx'] = ctrl('RR_RT', 'RR_RA[96,32] + RR_RB[96,32]', 0xC, 4, 0x00010203)
BODIES['cdx'] = ctrl('RR_RT', 'RR_RA[96,32] + RR_RB[96,32]', 0x8, 8, 0x0001020304050607)

# ---- select masks and bit gathers ---------------------------------------
BODIES['fsmbi'] = select_mask('RI16_RT', 'RI16_I16', 16, 8, immediate=True)
BODIES['fsmb']  = select_mask('RI7_RT',  'RI7_RA[96,32]', 16, 8)
BODIES['fsmh']  = select_mask('RI7_RT',  'RI7_RA[96,32]',  8, 16)
BODIES['fsm']   = select_mask('RI7_RT',  'RI7_RA[96,32]',  4, 32)
BODIES['gb']    = gather('RI7_RT', 'RI7_RA',  4, 32)
BODIES['gbh']   = gather('RI7_RT', 'RI7_RA',  8, 16)
BODIES['gbb']   = gather('RI7_RT', 'RI7_RA', 16,  8)

# ---- byte/word population and leading zeros -----------------------------
BODIES['cntb'] = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},8] = popcount(RI7_RA[{o},8]);' for o in B] + ['    RI7_RT = t;'])
BODIES['clz']  = '\n'.join(['    local t:16 = 0;'] +
    [f'    t[{o},32] = lzcount(RI7_RA[{o},32]);' for o in W] + ['    RI7_RT = t;'])

# ---- control flow: the condition and the target are in the preferred slot -
BODIES['brnz'] = '    if (RI16_RT[96,32] != 0)\n        goto targetAddress;'
BODIES['brz']  = '    if (RI16_RT[96,32] == 0)\n        goto targetAddress;'
BODIES['brhnz']= '    if (RI16_RT[112,16] != 0)\n        goto targetAddress;'
BODIES['brhz'] = '    if (RI16_RT[112,16] == 0)\n        goto targetAddress;'
BODIES['brsl'] = '    local t:16 = 0;\n    t[96,32] = inst_next;\n    RI16_RT = t;\n    call targetAddress;'
BODIES['brasl']= '    local t:16 = 0;\n    t[96,32] = inst_next;\n    RI16_RT = t;\n    call absoluteAddress;'


# ---- integer multiplies: SPU multiplies 16x16 -> 32 within each word ------
def mpy_body(rt, a_expr, b_expr, ra='RR_RA', rb='RR_RB', acc=None, shift16=False):
    out = ['    local t:16 = 0;']
    for i, o in enumerate(W):
        out.append(f'    local ma{i}:4 = {a_expr.format(r=ra, o=o)};')
        out.append(f'    local mb{i}:4 = {b_expr.format(r=rb, o=o)};')
        p = f'ma{i} * mb{i}'
        if shift16:
            p = f'({p}) << 16'
        if acc:
            p = f'({p}) + {acc}[{o},32]'
        out.append(f'    t[{o},32] = {p};')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

SL = 'sext({r}[{o},16]:2)'          # low  halfword, signed   -- :2 slices the low half
SLU = 'zext({r}[{o},16]:2)'
def lo(sign):  return ('sext' if sign else 'zext') + '({r}[' + '{o}' + '+0,16])'
LO_S, LO_U = 'sext({r}[{o},16])', 'zext({r}[{o},16])'
HI_S, HI_U = 'sext({r}[{o}+16,16])', 'zext({r}[{o}+16,16])'
def _fmt(e):  # resolve the {o}+16 arithmetic at generation time
    return e
def mk(a, b, **kw):
    def build(head):
        A = a.replace('{o}+16', 'HI').replace('{o}', 'LO')
        return None
    return None

def lanes_mpy(rt, asel, bsel, ra, rb, acc=None, shift16=False):
    out = ['    local t:16 = 0;']
    for i, o in enumerate(W):
        hi, lo_ = o + 16, o
        out.append(f'    local ma{i}:4 = {asel(ra, hi, lo_)};')
        out.append(f'    local mb{i}:4 = {bsel(rb, hi, lo_)};')
        p = f'ma{i} * mb{i}'
        if shift16: p = f'({p}) << 16'
        if acc:     p = f'({p}) + {acc}[{o},32]'
        out.append(f'    t[{o},32] = {p};')
    out.append(f'    {rt} = t;')
    return '\n'.join(out)

LOs  = lambda r, hi, lo: f'sext({r}[{lo},16])'
LOu  = lambda r, hi, lo: f'zext({r}[{lo},16])'
HIs  = lambda r, hi, lo: f'sext({r}[{hi},16])'
HIu  = lambda r, hi, lo: f'zext({r}[{hi},16])'
IMMs = lambda r, hi, lo: 'RI10_I10'

BODIES['mpy']     = lanes_mpy('RR_RT',  LOs, LOs, 'RR_RA', 'RR_RB')
BODIES['mpyu']    = lanes_mpy('RR_RT',  LOu, LOu, 'RR_RA', 'RR_RB')
BODIES['mpyh']    = lanes_mpy('RR_RT',  HIs, LOs, 'RR_RA', 'RR_RB', shift16=True)
BODIES['mpyhh']   = lanes_mpy('RR_RT',  HIs, HIs, 'RR_RA', 'RR_RB')
BODIES['mpyhhu']  = lanes_mpy('RR_RT',  HIu, HIu, 'RR_RA', 'RR_RB')
BODIES['mpyhha']  = lanes_mpy('RR_RT',  HIs, HIs, 'RR_RA', 'RR_RB', acc='RR_RT')
BODIES['mpyhhau'] = lanes_mpy('RR_RT',  HIu, HIu, 'RR_RA', 'RR_RB', acc='RR_RT')
BODIES['mpyi']    = lanes_mpy('RI10_RT', LOs, IMMs, 'RI10_RA', None)
BODIES['mpyui']   = lanes_mpy('RI10_RT', LOu, IMMs, 'RI10_RA', None)
BODIES['mpya']    = lanes_mpy('RRR_RT', LOs, LOs, 'RRR_RA', 'RRR_RB', acc='RRR_RC')

# ---- shufb: the whole reason the register file had to be widened ---------
# Output byte i is chosen by control byte i:
#   c & 0xC0 == 0x80 -> 0x00 ;  c & 0xE0 == 0xC0 -> 0xFF ;  c & 0xE0 == 0xE0 -> 0x80
#   otherwise        -> byte (c & 0x1F) of the 32-byte concatenation A||B
# Written branchlessly so the decompiler folds it away whenever the control is
# a constant -- which, with cwd/cbd/cwx now modelled, includes every mask built
# from a known address.
def shufb_body():
    out = ['    local t:16 = 0;']
    for i, o in enumerate(B):
        out += [
            f'    local c{i}:4 = zext(RRR_RC[{o},8]);',
            f'    local x{i}:4 = c{i} & 0x1F;',
            f'    local pa{i}:16 = RRR_RA >> ((15 - x{i}) * 8);',
            f'    local pb{i}:16 = RRR_RB >> ((31 - x{i}) * 8);',
            f'    local sv{i}:16 = pa{i} | pb{i};',
            f'    local sb{i}:4 = zext(sv{i}:1);',
            f'    local hi{i}:4 = c{i} & 0xE0;',
            f'    local mz{i}:4 = -zext((c{i} & 0xC0) == 0x80);',
            f'    local mf{i}:4 = -zext(hi{i} == 0xC0);',
            f'    local mh{i}:4 = -zext(hi{i} == 0xE0);',
            f'    local kp{i}:4 = ~(mz{i} | mf{i} | mh{i});',
            f'    local rr{i}:4 = (sb{i} & kp{i}) | (mf{i} & 0xFF) | (mh{i} & 0x80);',
            f'    t[{o},8] = rr{i}:1;',
        ]
    out.append('    RRR_RT = t;')
    return '\n'.join(out)

# Default OFF. Measured on metldr+isoldr: modelling shufb fully removes every
# remaining intrinsic (1342 -> 13) but inflates the C 3.7x and makes 5 functions
# per binary fail to decompile outright. It only pays where the control mask is
# a compile-time constant (~5% of sites); the dominant case -- a mask built by
# cwd/cbd from a *runtime* address -- expands into per-byte soup that is worse
# to read than the opaque intrinsic. Turn it on for constant-permutation code.
if os.environ.get('SPU_SHUFB', '0') != '0':
    BODIES['shufb'] = shufb_body()

# ================================================================ splicer ==
SRC = os.path.join(os.path.dirname(__file__), 'baseline')
DST = os.path.join(os.path.dirname(__file__), 'work')

def widen(s):
    s = s.replace("define register offset=0 size=8 [\n    lr sp r2",
                  "define register offset=0 size=16 [\n    lr sp r2", 1)
    names = ['lr', 'sp'] + [f'r{i}' for i in range(2, 128)]
    aliases = "\n".join(f"define register offset=0x{16*i:x} size=4 [ {n}_p ];"
                        for i, n in enumerate(names))
    old = ("# 4-byte view of the low half of sp, matching the 4-byte ram address space.\n"
           "# Without this the stack pointer (8 bytes) cannot be a spacebase for a 4-byte\n"
           "# address space, which produced BADSPACEBASE and (int)(double) casts everywhere.\n"
           "define register offset=12 size=4 [ sp_lo ];\n")
    assert old in s
    s = s.replace(old,
        "# Preferred-slot views: quadword bytes 0..3, i.e. the MOST significant 4\n"
        "# bytes of each 16-byte register in this big-endian register space.\n"
        "# Every SPU scalar -- addresses, branch conditions, return values -- is here.\n"
        + aliases + "\n")
    s = s.replace("define register offset=0x400 size=8 pc;",
                  "define register offset=0x1800 size=8 pc;", 1)
    s = s.replace("define register offset=0x800 size=8 [\n    ch0",
                  "define register offset=0x800 size=16 [\n    ch0", 1)
    return s

def decode_fixes(s):
    """Decode-table bugs in upstream GhidraSPU, found by diffing Ghidra's
    disassembly against spu-elf-objdump on a generated test program."""
    reps = [
        # cgthi had the wrong primary opcode, so it did not decode AT ALL.
        # RI10 compare-immediate opcodes run 0x4C/0x4D/0x4E = cgti/cgthi/cgtbi;
        # the spec had 115 (0x73) where 77 (0x4D) belongs.
        (":cgthi RI10_RT,RI10_RA,RI10_I10 is RI10_OP=115",
         ":cgthi RI10_RT,RI10_RA,RI10_I10 is RI10_OP=77"),
        # rotqbi/rotqbii had their operand *forms* swapped: the register form was
        # declared with RI7 fields (reading the RB register number as a 6-bit
        # immediate) and the immediate form with RR fields. Same for rotqmbi.
        (":rotqbi RI7_RT,RI7_RA,RI7_I7 is RI7_OP=472 & RI7_RT & RI7_RA & RI7_I7",
         ":rotqbi RR_RT,RR_RA,RR_RB is RR_OP=472 & RR_RT & RR_RA & RR_RB"),
        (":rotqbii RR_RT,RR_RA,RR_RB is RR_OP=504 & RR_RT & RR_RA & RR_RB",
         ":rotqbii RI7_RT,RI7_RA,RI7_I7 is RI7_OP=504 & RI7_RT & RI7_RA & RI7_I7"),
        (":rotqmbi RI7_RT,RI7_RA,RI7_I7 is RI7_OP=473 & RI7_RT & RI7_RA & RI7_I7",
         ":rotqmbi RR_RT,RR_RA,RR_RB is RR_OP=473 & RR_RT & RR_RA & RR_RB"),
    ]
    for a, b in reps:
        assert a in s, f"decode fixup target missing: {a[:60]}"
        s = s.replace(a, b)
    return s

BODY_RE = re.compile(r'^(:(\S+)[^\n]*\n)\{\n(.*?)^\}\n', re.M | re.S)

def splice(s):
    used, skipped = set(), []
    def sub(m):
        head, mn, body = m.group(1), m.group(2), m.group(3)
        if mn in BODIES:
            used.add(mn)
            b = BODIES[mn]
            b = b(head) if callable(b) else b
            return f"{head}{{\n{b}\n}}\n"
        skipped.append(mn)
        return m.group(0)
    s = BODY_RE.sub(sub, s)
    return s, used, skipped

def fixups(s):
    """Constructors with several variants, patched by content rather than name."""
    def rep(pat, sub, expect_min=1):
        nonlocal s
        s, n = re.subn(pat, sub, s, flags=re.M)
        assert n >= expect_min, f"fixup matched {n} times: {pat}"
    # indirect branch / return: the destination is the preferred slot
    rep(r'^(\s*)return \[RR_RA\];',
        r'\1local d:4 = RR_RA[96,32];\n\1return [d];', 4)
    rep(r'^(\s*)goto \[RR_RA\];',
        r'\1local d:4 = RR_RA[96,32];\n\1goto [d];', 4)
    rep(r'\(RR_RT:2\)', 'RR_RT[112,16]', 4)
    rep(r'\bRR_RT (!=|==) 0\) goto inst_next;', r'RR_RT[96,32] \1 0) goto inst_next;', 4)
    # LSA: address from the preferred slot; the hardware forces 16-byte alignment
    rep(r'\{ local ea:8 = symbol \+ RI10_RA; tmp:4 = ea:4; export tmp; \}',
        '{ local ea:4 = RI10_RA[96,32] + symbol; tmp:4 = ea & 0xFFFFFFF0; export tmp; }')
    # a remaining ":4" slice of a register means "low word"; the scalar is the high word
    rep(r'\b(RR_RA|RR_RB|RR_RT|RI7_RA|RI7_RT|RI10_RA|RI10_RT|RRR_RA|RRR_RB|RRR_RC):4\b',
        r'\1[96,32]')
    return s

if __name__ == '__main__':
    sinc = open(os.path.join(SRC, 'spu.sinc')).read()
    sinc = widen(sinc)
    sinc = decode_fixes(sinc)
    sinc, used, skipped = splice(sinc)
    sinc = fixups(sinc)
    open(os.path.join(DST, 'spu.sinc'), 'w').write(sinc)

    c = open(os.path.join(SRC, 'spu.cspec')).read()
    c = c.replace('<stackpointer register="sp_lo" space="ram"/>',
                  '<stackpointer register="sp_p" space="ram"/>')
    abi = os.environ.get('SPU_ABI', 'slot')
    if abi == 'slot':
        # Keep the FULL 16-byte register as the parameter's home, but claim only
        # 4 bytes of it. Big-endian, so Ghidra places the value in bytes 0..3 --
        # the preferred slot, where the hardware puts it -- while still treating
        # the register as a known input, so a callee that reads the whole
        # quadword resolves. extension="none": sign-filling the other 12 bytes
        # makes every `ai rX,r3,n` come out as ((int)arg >> 0x1f) + n.
        c = re.sub(r'<pentry minsize="1" maxsize="\d+" extension="sign">',
                   '<pentry minsize="1" maxsize="4" extension="none">', c)
    elif abi == 'wide':
        # Pass in the WHOLE 128-bit register. Big-endian, so a 4-byte argument
        # lands in bytes 0..3 -- the preferred slot -- which is what the hardware
        # does. Claiming only 4 bytes (a pentry on rN_p) makes Ghidra treat the
        # other 12 as not-an-input, and any callee that reads the full quadword
        # (every `ori rX,r3,0` does) then resolves to garbage.
        c = re.sub(r'(<pentry minsize="1" )maxsize="\d+"', r'\1maxsize="16"', c)
    else:
        c = re.sub(r'<register name="(r\d+|lr|sp)"/>', r'<register name="\1_p"/>', c)
    open(os.path.join(DST, 'spu.cspec'), 'w').write(c)

    print(f"rewrote {len(used)} constructor bodies")
    miss = sorted(set(BODIES) - used)
    if miss:  print("  table entries never matched:", miss)
    print(f"  left alone ({len(set(skipped))}):", " ".join(sorted(set(skipped))))
