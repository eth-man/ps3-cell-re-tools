#!/usr/bin/env python3
"""Offline PPC64 emulator harness for the lv1 iso-load handler chain.

Runs lv1 functions (0x2b80a8 and callees) under Unicorn with CATCH-AND-MOCK,
entirely offline -- no console, no RSOD.  This is the reliable executor that
replaces the push->launch->crash loop for mapping the reachability chain.

Why this is non-trivial (all fixed here; see notes/157):
  1. Unicorn's default PPC core is a 32-bit 750-class CPU -- GPR writes silently
     don't commit and mflr/std raise spurious traps.  ctl_set_cpu_model(970FX)
     (the Cell PPE lineage) fixes ALU/SPR/branch execution.
  2. MSR cannot be set (reg_write(MSR) never sticks, mtmsrd faults) so the core
     stays in 32-bit mode.  Every 64-bit ld/std/ldarx/stdcx -- i.e. every lv1
     pointer deref -- then raises intno 96 ("64-bit op in 32-bit mode").
  3. We SHIM that whole family in software (catch-and-mock at instruction level):
       - intno 96 fires with PC ALREADY advanced past the faulter (shim PC-4);
       - on the faulting emu_start's *return* Unicorn rolls the register file
         back to the translation-block entry, so we snapshot the regs INSIDE the
         INTR hook (still correct there) and restore them before shimming;
       - the RA=0 => literal-0 rule applies to the ADDRESS BASE only, never to
         the RT/RS source register.
  4. Because every struct deref is a shimmed op, the shim is also our discovery
     instrument: it demand-maps any unmapped effective address (zero page) and
     logs every field read/write, so a forged object reveals exactly which
     fields the chain requires -- in ONE offline pass.

lv1 ELF VAs == runtime real addresses, so r2 (TOC) and function addresses map
1:1.  lwarx/stwcx run as plain load/store single-threaded, so a forged lock
word of 0 breaks the 0x31a028 acquire naturally.
"""
import struct, sys
from unicorn import *
from unicorn.ppc_const import *

ELF   = 'extracted/corpus/493/lv1.elf'
R2    = 0x35a038                 # lv1 TOC base (r2)
PAGE  = 0x1000
MASK  = 0xffffffffffffffff
CPU   = UC_CPU_PPC64_970FX_V3_1

GPR   = [getattr(sys.modules['unicorn.ppc_const'],'UC_PPC_REG_%d'%i) for i in range(32)]
SPR   = [UC_PPC_REG_LR, UC_PPC_REG_CTR, UC_PPC_REG_CR, UC_PPC_REG_PC]
SNAPREGS = GPR + SPR

def alignd(x): return x & ~(PAGE-1)
def alignu(x): return (x + PAGE-1) & ~(PAGE-1)
def exts(v,bits): m=1<<(bits-1); return (v^m)-m

def load_segments(uc, f):
    ph=struct.unpack_from('>Q',f,0x20)[0]
    phe=struct.unpack_from('>H',f,0x36)[0]
    phn=struct.unpack_from('>H',f,0x38)[0]
    mapped=[]
    for i in range(phn):
        t,fl,off,va,pa,fsz,msz,al=struct.unpack_from('>IIQQQQQQ',f,ph+i*phe)
        if t!=1 or msz==0: continue
        lo=alignd(va); hi=alignu(va+msz)
        uc.mem_map(lo, hi-lo)
        uc.mem_write(va, f[off:off+fsz])
        mapped.append((lo,hi))
    return mapped

class Emu:
    def __init__(self, verbose=True):
        self.uc=Uc(UC_ARCH_PPC, UC_MODE_PPC64|UC_MODE_BIG_ENDIAN)
        self.uc.ctl_set_cpu_model(CPU)
        f=open(ELF,'rb').read()
        self.mapped=load_segments(self.uc,f)
        self.demand=set()           # pages we had to demand-map (discovered structs)
        self.access=[]              # (pc, 'R'/'W', ea, size, value) -- field-access log
        self.calls=[]               # (site, target) bl edges
        self.shimmed=0
        self.verbose=verbose
        # forge arena + stack, placed at LOW real addresses (lv1's world is <8MB
        # of image; keep ours clear of it).  All 64-bit ops are shimmed so the
        # absolute address has no 32-bit-mode limit.
        self.ARENA=0x10000000; self.uc.mem_map(self.ARENA, 0x400000)   # forged objects
        self.STACK=0x1f000000; self.uc.mem_map(self.STACK, 0x100000)   # stack
        self.RET=0xdead0000;   self.uc.mem_map(alignd(self.RET), PAGE) # return sentinel
        self._snap=None
        self._pend_cr=None
        # Shadow TIME BASE.  Unicorn's mftb always yields 0, and lv1 spins on
        # `mftb; cmpwi 0; beq -8` (0x304fbc) waiting for a NONZERO tb -- an
        # infinite loop offline that never happens on silicon.  We advance a
        # shadow counter and satisfy mftb ourselves.  (notes/157 claimed this
        # fix; it was NOT in the file -- re-added 2026-08-30.)
        self._tb=0x1000
        self._mftb_at=None
        self._resume=False
        self._hooks()

    # ---- memory helpers ------------------------------------------------------
    def _ensure(self, ea, size):
        """Map any page the [ea,ea+size) range needs; record as discovered."""
        p=alignd(ea); end=ea+size
        while p<end:
            if not self._is_mapped(p):
                self.uc.mem_map(p, PAGE); self.demand.add(p)
            p+=PAGE
    def _is_mapped(self, a):
        for lo,hi in self.mapped:
            if lo<=a<hi: return True
        for lo,sz in [(self.ARENA,0x400000),(self.STACK,0x100000),(alignd(self.RET),PAGE)]:
            if lo<=a<lo+sz: return True
        return alignd(a) in self.demand

    # ---- CR / rotate-mask helpers -------------------------------------------
    def _set_crf(self, bf, lt, gt, eq):
        cr=self.uc.reg_read(UC_PPC_REG_CR)
        so=(self.uc.reg_read(UC_PPC_REG_CR)>>(28-bf*4))&1   # keep SO bit
        nib=(lt<<3)|(gt<<2)|(eq<<1)|so
        sh=28-bf*4
        cr=(cr & ~(0xf<<sh)) | (nib<<sh)
        self.uc.reg_write(UC_PPC_REG_CR, cr&MASK)
    def _cr0_signed(self, v):
        s=exts(v&MASK,64)
        self._set_crf(0, s<0, s>0, s==0)
    @staticmethod
    def _rotl64(v, sh):
        sh&=63
        return ((v<<sh)|((v&MASK)>>(64-sh)))&MASK if sh else v&MASK
    @staticmethod
    def _mask64(mb, me):
        m=0; i=mb&63
        while True:
            m|=1<<(63-i)
            if i==(me&63): break
            i=(i+1)&63
        return m&MASK

    # ---- the 64-bit op shim (catch-and-mock instruction level) --------------
    def _shim(self, addr):
        uc=self.uc
        ins=struct.unpack('>I',uc.mem_read(addr,4))[0]
        op=ins>>26; rt=(ins>>21)&31; ra=(ins>>16)&31; rb=(ins>>11)&31; rc=ins&1
        base=lambda r:(uc.reg_read(GPR[r]) if r else 0)   # RA=0 => literal 0 (addr base)
        reg =lambda r: uc.reg_read(GPR[r])                # actual reg value
        wr  =lambda r,v: uc.reg_write(GPR[r], v&MASK)
        def loadN(ea,n,signed=False):
            self._ensure(ea,n); v=int.from_bytes(uc.mem_read(ea,n),'big')
            if signed: v=exts(v,n*8)&MASK
            self.access.append((addr,'R',ea,n,v)); return v
        def storeN(ea,n,val):
            self._ensure(ea,n); uc.mem_write(ea,(val&((1<<(n*8))-1)).to_bytes(n,'big'))
            self.access.append((addr,'W',ea,n,val&MASK))

        if op in (58,62):                                  # DS-form ld/std
            ds=exts(ins&0xfffc,16); ea=(base(ra)+ds)&MASK; xo=ins&3
            if op==58:
                v=loadN(ea,4,True) if xo==2 else loadN(ea,8); wr(rt,v)
                if xo==1 and ra: wr(ra,ea)
            else:
                storeN(ea,8,reg(rt))
                if xo==1 and ra: wr(ra,ea)
            return True

        if op==30:                                         # MD/MDS-form rotate+mask
            radest=ra; S=reg(rt); sub4=(ins>>1)&0xf
            if sub4 in (8,9):                              # MDS: rldcl / rldcr
                sh=reg(rb)&63; m6=(( (ins>>5)&0x3f &1)<<5)|(((ins>>5)&0x3f)>>1)
                rot=self._rotl64(S,sh)
                res=rot & (self._mask64(m6,63) if sub4==8 else self._mask64(0,m6))
            else:                                          # MD: rldicl/rldicr/rldic/rldimi
                sh=((ins>>11)&0x1f)|(((ins>>1)&1)<<5)
                field=(ins>>5)&0x3f; m6=((field&1)<<5)|(field>>1); sub=(ins>>2)&7
                rot=self._rotl64(S,sh)
                if   sub==0: res=rot & self._mask64(m6,63)          # rldicl
                elif sub==1: res=rot & self._mask64(0,m6)           # rldicr
                elif sub==2: res=rot & self._mask64(m6,63-sh)       # rldic
                elif sub==3:                                        # rldimi
                    mk=self._mask64(m6,63-sh); res=(rot&mk)|(reg(radest)&(~mk&MASK))
                else: return False
            wr(radest,res)
            if rc: self._cr0_signed(res)
            return True

        if op==31:
            xo=(ins>>1)&0x3ff
            # --- 64-bit memory (X-form indexed / atomics) ---
            if xo in (21,53,341,373,149,181,84,214):
                ea=(base(ra)+reg(rb))&MASK
                if   xo in (21,53):  wr(rt,loadN(ea,8)); (xo==53 and ra) and wr(ra,ea)
                elif xo in (341,373):wr(rt,loadN(ea,4,True)); (xo==373 and ra) and wr(ra,ea)
                elif xo in (149,181):storeN(ea,8,reg(rt)); (xo==181 and ra) and wr(ra,ea)
                elif xo==84:         wr(rt,loadN(ea,8))                       # ldarx
                elif xo==214:        storeN(ea,8,reg(rt)); self._set_crf(0,0,0,1)  # stdcx. -> success
                return True
            # --- 64-bit ALU (dest RA for shifts/logical-extend, RT for mul/div) ---
            A=reg(ra); B=reg(rb); S=reg(rt)
            def sA(x):  # signed 64
                return exts(x&MASK,64)
            if   xo==27:   res=(S<<(B&0x7f))&MASK if (B&0x40)==0 else 0; wr(ra,res); rc and self._cr0_signed(res); return True  # sld
            elif xo==539:  res=((S&MASK)>>(B&0x7f)) if (B&0x40)==0 else 0; wr(ra,res); rc and self._cr0_signed(res); return True  # srd
            elif xo==794:  n=B&0x7f; res=(sA(S)>>min(n,63))&MASK; wr(ra,res); rc and self._cr0_signed(res); return True          # srad
            elif (xo>>1)==413: sh=((ins>>11)&0x1f)|(((ins>>1)&1)<<5); res=(sA(S)>>min(sh,63))&MASK; wr(ra,res); rc and self._cr0_signed(res); return True  # sradi (XS-form, xo=826/827)
            elif xo==233:  res=(sA(A)*sA(B))&MASK; wr(rt,res); rc and self._cr0_signed(res); return True                        # mulld
            elif xo==73:   res=((sA(A)*sA(B))>>64)&MASK; wr(rt,res); rc and self._cr0_signed(res); return True                  # mulhd
            elif xo==9:    res=((A*B)>>64)&MASK; wr(rt,res); rc and self._cr0_signed(res); return True                          # mulhdu
            elif xo==489:  d=sA(B); res=(int(sA(A)/d)&MASK) if d else 0; wr(rt,res); rc and self._cr0_signed(res); return True   # divd
            elif xo==457:  res=(A//B)&MASK if B else 0; wr(rt,res); rc and self._cr0_signed(res); return True                   # divdu
            elif xo==986:  res=exts(S&0xffffffff,32)&MASK; wr(ra,res); rc and self._cr0_signed(res); return True                # extsw
            elif xo==58:   v=S&MASK; res=64 if v==0 else (64-v.bit_length()); wr(ra,res); rc and self._cr0_signed(res); return True  # cntlzd
            elif xo==178:  return True                                       # mtmsrd -> no-op (MSR unmodelled)
            elif xo==83:   wr(rt,0); return True                             # mfmsr -> 0
            elif xo in (0,32):                                               # cmp/cmpl (L=1 => 64-bit)
                bf=(ins>>23)&7; L=(ins>>21)&1
                if xo==0: a,b=(sA(A),sA(B)) if L else (exts(A&0xffffffff,32),exts(B&0xffffffff,32))
                else:     a,b=((A,B) if L else (A&0xffffffff,B&0xffffffff))
                self._set_crf(bf, a<b, a>b, a==b); return True
        return False

    # ---- hooks ---------------------------------------------------------------
    def _hooks(self):
        uc=self.uc
        def code(uc,addr,size,ud):
            # Apply a pending 64-bit compare fixup from the PREVIOUS instruction.
            # Unicorn's 32-bit core executes cmpd/cmpld/cmpdi/cmpldi TRUNCATED to 32
            # bits (no fault), so it mis-sets CR for operands differing only in high
            # bits. We recompute correctly and overwrite CR just before the consumer.
            if self._pend_cr is not None:
                bf,nib=self._pend_cr; sh=28-bf*4
                cr=uc.reg_read(UC_PPC_REG_CR); so=(cr>>sh)&1
                uc.reg_write(UC_PPC_REG_CR, (cr & ~(0xf<<sh)) | (((nib&0xe)|so)<<sh))
                self._pend_cr=None
            try: w=struct.unpack('>I',uc.mem_read(addr,4))[0]
            except Exception: return
            op=w>>26
            if op in (10,11,31):                           # cmpli/cmpi / cmp-cmpl family
                is_x = op==31; xo=(w>>1)&0x3ff
                if (not is_x) or xo in (0,32):
                    L=(w>>21)&1
                    if L:                                  # 64-bit compare: fix it
                        bf=(w>>23)&7; ra=(w>>16)&31; a=uc.reg_read(GPR[ra])&MASK
                        if is_x: b=uc.reg_read(GPR[(w>>11)&31])&MASK; signed=(xo==0)
                        elif op==11: b=exts(w&0xffff,16)&MASK; signed=True   # cmpdi
                        else: b=(w&0xffff)&MASK; signed=False                 # cmpldi
                        if signed: a=exts(a,64); b=exts(b,64)
                        nib=(8 if a<b else 0)|(4 if a>b else 0)|(2 if a==b else 0)
                        self._pend_cr=(bf,nib)
            if op==18 and (w&1):                           # bl (AA=0)
                off=w&0x03fffffc
                if off&0x02000000: off-=0x04000000
                self.calls.append((addr,(addr+off)&MASK))
            # mftb: satisfy from the SHADOW TIME BASE at execution time.  Unicorn
            # yields 0 forever, and lv1 spins on `mftb; cmpwi 0; beq -8` waiting
            # for a nonzero tb -- an offline-only infinite loop.  We stop here so
            # the driver loop can write the value and step over it.
            if op==31 and ((w>>1)&0x3ff)==371:
                self._mftb_at=addr
                uc.emu_stop()
        uc.hook_add(UC_HOOK_CODE, code)
        def unmapped(uc,access,addr,size,value,ud):
            # 32-bit native ld/st to an unmapped page: demand-map + retry.
            self._ensure(addr,size); self.demand.add(alignd(addr)); return True
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED|UC_HOOK_MEM_WRITE_UNMAPPED|UC_HOOK_MEM_FETCH_UNMAPPED, unmapped)
        def intr(uc,intno,ud):
            self._intno=intno
            self._snap=[uc.reg_read(r) for r in SNAPREGS]  # capture BEFORE rollback
            uc.emu_stop()
        uc.hook_add(UC_HOOK_INTR, intr)

    # ---- register access -----------------------------------------------------
    def gpr(self,n): return self.uc.reg_read(GPR[n])
    def setgpr(self,n,v): self.uc.reg_write(GPR[n],v&MASK)

    # ---- driver loop ---------------------------------------------------------
    # ---- mftb interception ---------------------------------------------
    def _try_mftb(self, addr):
        """If addr holds mftb/mftbu, satisfy it from the shadow TB and step over.
        Returns True if handled.  mftb = op31, XO=371, SPR 268(TB)/269(TBU)."""
        try: ins=struct.unpack('>I',self.uc.mem_read(addr,4))[0]
        except Exception: return False
        if (ins>>26)!=31 or ((ins>>1)&0x3ff)!=371: return False
        rt=(ins>>21)&31
        f=(ins>>11)&0x3ff; spr=((f&0x1f)<<5)|((f>>5)&0x1f)
        self._tb=(self._tb+0x100)&MASK
        val=self._tb if spr==268 else (self._tb>>32)
        self.uc.reg_write(GPR[rt], val&MASK)
        self.uc.reg_write(UC_PPC_REG_PC, (addr+4)&MASK)
        return True

    def run(self, entry, regs, maxsteps=4000, r2=R2, stop_at=None):
        """regs: dict {gpr_num: value}. Returns ('DONE'|'INTR'|'ERR'|'MAX', pc)."""
        uc=self.uc
        self.setgpr(1, self.STACK+0x80000); self.setgpr(2, r2)
        for n,v in regs.items(): self.setgpr(n,v)
        uc.reg_write(UC_PPC_REG_LR, self.RET)
        pc=entry
        for step in range(maxsteps):
            self._intno=None; self._snap=None; self._mftb_at=None
            try:
                uc.emu_start(pc, self.RET, count=1000000)
            except UcError as e:
                return ('ERR', uc.reg_read(UC_PPC_REG_PC), str(e))
            pc=uc.reg_read(UC_PPC_REG_PC)
            if self._intno is not None:
                if self._intno==96:                        # 64-bit op: restore+shim
                    for r,v in zip(SNAPREGS,self._snap): uc.reg_write(r,v)
                    cur=uc.reg_read(UC_PPC_REG_PC)
                    if not self._shim(cur-4):
                        w=struct.unpack('>I',uc.mem_read(cur-4,4))[0]
                        return ('UNSHIMMED', cur-4, "op=%d xo=%d w=0x%08x"%(w>>26,(w>>1)&0x3ff,w))
                    self.shimmed+=1
                    pc=uc.reg_read(UC_PPC_REG_PC)
                    if stop_at is not None and pc==stop_at: return ('STOP', pc)
                    continue
                return ('INTR', pc, self._intno)            # other trap: real stop
            if pc==self.RET or pc==(self.RET&MASK):
                return ('DONE', uc.reg_read(UC_PPC_REG_3)&MASK)
            if stop_at is not None and pc==stop_at: return ('STOP', pc)
            # Execution stopped WITHOUT returning to the LR sentinel.  Previously
            # this fell through to ('DONE', r3), which laundered an infinite spin
            # loop into a success (CREATE 0x2b7d88 burned the 1M-instruction
            # budget in the 0x304fbc mftb loop and still reported DONE).
            # Handle mftb here; anything else is a REAL stall, reported as such.
            if self._mftb_at is not None and self._try_mftb(self._mftb_at):
                self._mftb_at=None; pc=uc.reg_read(UC_PPC_REG_PC); continue
            if self._try_mftb(pc):
                pc=uc.reg_read(UC_PPC_REG_PC); continue
            return ('STALLED', pc, 'emu_start stopped without reaching RET')
        return ('MAX', pc)

    # ---- reporting -----------------------------------------------------------
    def report(self):
        print("  shimmed 64-bit ops: %d   demand-mapped pages: %d   bl-calls: %d"%(
            self.shimmed,len(self.demand),len(self.calls)))
        if self.demand:
            print("  discovered (demand-mapped) pages: %s"%(
                ", ".join("0x%x"%p for p in sorted(self.demand))))

if __name__=='__main__':
    e=Emu()
    MSG=e.ARENA+0x800
    m=bytearray(0x60)
    struct.pack_into('>Q',m,0x28,1)      # message handle id
    e.uc.mem_write(MSG, bytes(m))
    print("=== emulate 0x2b80a8 (iso-load handler) msg@0x%x ==="%MSG)
    res=e.run(0x2b80a8, {3:MSG})
    print("  result:", res)
    e.report()
    # show first field accesses into the message + globals
    print("  first 40 field accesses:")
    for pc,rw,ea,sz,v in e.access[:40]:
        print("    pc=0x%08x %s [0x%09x]:%d = 0x%x"%(pc,rw,ea,sz,v))
