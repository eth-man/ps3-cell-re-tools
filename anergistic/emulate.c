// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.h"
#include "types.h"
#include "emulate.h"
#include "main.h"
#include "emulate-instrs.h"
#include "helper.h"
#include "gdb.h"

static u32 instr;

static u32 op;
static u32 ra;
static u32 rb;
static u32 rc;
static u32 rt;
static u32 ix;


/* --- Which instructions actually WRITE rt?
   The dispatch below applies taint by ENCODING CLASS, but the rt field is not a
   destination in every instruction of a class:
     - hbra/hbrr : branch HINTS. rt bits are part of the branch target; no register
                   is written.  Clearing reg_taint[rt] here destroys live taint on a
                   quasi-arbitrary register, on an instruction the compiler emits
                   constantly.  (This was the bug: metldr's header-copy loop has
                   `hbrr` at 0x1d04 whose rt field decodes to r11 -- the very register
                   holding the loaded header -- so taint died every iteration.)
     - br/bra    : rt bits are part of the target.
     - brz/brnz/brhz/brhnz, bi/biz/binz/bihz/bihnz : rt is the CONDITION/target SOURCE.
     - stqd/stqx/stqa/stqr : rt is the STORED DATA source.
     - wrch, stopd, mtspr  : rt is the source operand.
   For all of these, rt's taint must be left exactly as it is. --- */

/* A channel write, an indirect branch target and an LS address operand all latch
   only WORD 0 of the quadword (lanes 0-3).  Taint in lanes 4-15 is real taint on
   the register but cannot reach the sink, so testing the whole quadword (as
   taint_reg_any does) manufactures false positives -- e.g. MFC_LSA appearing
   attacker-controlled when only lane 4-7 carried taint and the latched word was
   metldr's own immediate. */
static u32 taint_word0(u32 r)
{
	int i;
	for (i = 0; i < 4; i++) if (reg_taint[r][i]) return reg_taint[r][i];
	return 0;
}

static int rt_is_dest(const void *fn)
{
	return !(fn == (const void *)instr_hbra  || fn == (const void *)instr_hbrr  ||
	         fn == (const void *)instr_br    || fn == (const void *)instr_bra   ||
	         fn == (const void *)instr_brz   || fn == (const void *)instr_brnz  ||
	         fn == (const void *)instr_brhz  || fn == (const void *)instr_brhnz ||
	         fn == (const void *)instr_bi    || fn == (const void *)instr_biz   ||
	         fn == (const void *)instr_binz  || fn == (const void *)instr_bihz  ||
	         fn == (const void *)instr_bihnz ||
	         fn == (const void *)instr_stqd  || fn == (const void *)instr_stqx  ||
	         fn == (const void *)instr_stqa  || fn == (const void *)instr_stqr  ||
	         fn == (const void *)instr_wrch  || fn == (const void *)instr_stopd ||
	         fn == (const void *)instr_mtspr);
}

/* iohl ORs an immediate INTO rt -- rt is both source and destination, so its taint
   must be PRESERVED, not cleared like a fresh immediate load. */
static int rt_is_fresh_immediate(const void *fn)
{
	return fn != (const void *)instr_iohl;
}

static void taint_prop(u32 rt, const u32 *srcs, int nsrc)
{
	int i, k;
	if (taint_on <= 0 || taint_rt_set) return;      /* a load already set rt */
	for (i = 0; i < 16; i++) {
		u32 v = 0;
		for (k = 0; k < nsrc; k++) if (!v) v = reg_taint[srcs[k]][i];   /* first origin wins */
		reg_taint[rt][i] = v;
	}
}

#define instr_bits(start, end) (instr >> (31 - end)) & ((1 << (end - start + 1)) - 1)

static void decode_rr(void)
{
	rb = instr_bits(11, 17);
	ra = instr_bits(18, 24);
	rt = instr_bits(25, 31);
}

static void decode_rrr(void)
{
	rt = instr_bits(4, 10);
	rb = instr_bits(11, 17);
	ra = instr_bits(18, 24);
	rc = instr_bits(25, 31);
}

static void decode_ri7(void)
{
	ix = instr_bits(11, 17);
	ra = instr_bits(18, 24);
	rt = instr_bits(25, 31);
}

static void decode_ri10(void)
{
	ix = instr_bits(8, 17);
	ra = instr_bits(18, 24);
	rt = instr_bits(25, 31);
}

static void decode_ri16(void)
{
	ix = instr_bits(9, 24);
	rt = instr_bits(25, 31);
}

static void decode_ri18(void)
{
	ix = instr_bits(7, 24);
	rt = instr_bits(25, 31);
}

static int emulate_instr(void)
{
	op = instr_bits(0, 10);
	
	switch(instr_tbl[op].type) {
		case SPU_INSTR_RR:
			decode_rr();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_rr_t)instr_tbl[op].ptr)(rt, ra, rb);
			  u32 _s[2]; _s[0]=ra; _s[1]=rb; if (rt_is_dest(instr_tbl[op].ptr)) taint_prop(rt,_s,2); return _r; }
			break;
		case SPU_INSTR_RRR:
			decode_rrr();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_rrr_t)instr_tbl[op].ptr)(rt, ra, rb, rc);
			  u32 _s[3]; _s[0]=ra; _s[1]=rb; _s[2]=rc; if (rt_is_dest(instr_tbl[op].ptr)) taint_prop(rt,_s,3); return _r; }
			break;
		case SPU_INSTR_RI7:
			decode_ri7();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_ri7_t)instr_tbl[op].ptr)(rt, ra, ix);
			  u32 _s[1]; _s[0]=ra; if (rt_is_dest(instr_tbl[op].ptr)) taint_prop(rt,_s,1); return _r; }
			break;
		case SPU_INSTR_RI10:
			decode_ri10();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_ri10_t)instr_tbl[op].ptr)(rt, ra, ix);
			  u32 _s[1]; _s[0]=ra; if (rt_is_dest(instr_tbl[op].ptr)) taint_prop(rt,_s,1); return _r; }
			break;
		case SPU_INSTR_RI16:
			decode_ri16();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_ri16_t)instr_tbl[op].ptr)(rt, ix);
			  if (taint_on > 0 && !taint_rt_set && rt_is_dest(instr_tbl[op].ptr)
			      && rt_is_fresh_immediate(instr_tbl[op].ptr))
				  memset(reg_taint[rt], 0, sizeof reg_taint[rt]);  /* immediate: clears taint */
			  return _r; }
			break;
		case SPU_INSTR_RI18:
			decode_ri18();
			taint_rt_set = 0;
			{ int _r = ((spu_instr_ri18_t)instr_tbl[op].ptr)(rt, ix);
			  /* ila and friends load an IMMEDIATE -- the destination is fully
			     determined by the instruction, so its taint must be CLEARED.
			     Omitting this leaves every constant-loaded address register
			     carrying T=0 taint forever, which saturates the address sink. */
			  if (taint_on > 0 && !taint_rt_set && rt_is_dest(instr_tbl[op].ptr))
				  memset(reg_taint[rt], 0, sizeof reg_taint[rt]);
			  return _r; }
			break;
		case SPU_INSTR_SPECIAL:
			return ((spu_instr_special_t)instr_tbl[op].ptr)(instr);
			break;
		case SPU_INSTR_NONE:
		default:
			fail("Unknown instruction at %08x: %08x", ctx->pc, instr);
			return 1;
	}
}


/* ================= harness: fault injection =================
 * ANERG_STOP_PC=<hex>    stop when pc reaches this, print [RESULT] r3
 * ANERG_FAULT_AT=<n>     inject at instruction index n (0-based)
 * ANERG_FAULT_TYPE=      skip | zero | flip | rand | setall
 * ANERG_FAULT_REG=<n>    target register (default 3)
 * ANERG_FAULT_BIT=<n>    bit index for flip (0=LSB of word0)
 */
static long  hf_count   = 0;
static long  hf_at      = -1;
static int   hf_type    = 0;   /* 0 none 1 skip 2 zero 3 flip 4 rand 5 setall */
static int   hf_reg     = 3;
static int   hf_bit     = 31;
static long  hf_stop_pc = -1;
static int   hf_init    = 0;
static u32   hf_watch[16]; static int hf_nwatch = -1;
static unsigned char ww_prev[128]; static u32 ww_lo=0, ww_len=0; static int ww_init=0;
static long  hf_maxi    = 2000000;
static long  hf_nth = 1, hf_hits = 0;

static void harness_fault_init(void)
{
	const char *e;
	hf_init = 1;
	if ((e = getenv("ANERG_FAULT_AT")))  hf_at = strtol(e, NULL, 0);
	if ((e = getenv("ANERG_FAULT_REG"))) hf_reg = (int)strtol(e, NULL, 0);
	if ((e = getenv("ANERG_FAULT_BIT"))) hf_bit = (int)strtol(e, NULL, 0);
	if ((e = getenv("ANERG_STOP_PC")))   hf_stop_pc = strtol(e, NULL, 0);
	if ((e = getenv("ANERG_MAXI")))      hf_maxi = strtol(e, NULL, 0);
	if ((e = getenv("ANERG_STOP_NTH")))  hf_nth  = strtol(e, NULL, 0);
	if ((e = getenv("ANERG_FAULT_TYPE"))) {
		if      (!strcmp(e, "skip"))   hf_type = 1;
		else if (!strcmp(e, "zero"))   hf_type = 2;
		else if (!strcmp(e, "flip"))   hf_type = 3;
		else if (!strcmp(e, "rand"))   hf_type = 4;
		else if (!strcmp(e, "setall")) hf_type = 5;
	}
}

unsigned char *harness_cover_bits = NULL;
static void harness_cover_report(void)
{
	unsigned long n = 0, i;
	const char *want;
	if (!harness_cover_bits) return;
	for (i = 0; i < (0x40000u >> 2); i++)
		if (harness_cover_bits[i >> 3] & (1u << (i & 7))) n++;
	fprintf(stderr, "[COVER] %lu unique instruction addresses executed\n", n);

	/* ANERG_COVER_DUMP=<file> -> write every executed instruction address, one
	 * hex per line.  The count alone cannot tell you WHICH opcodes a window
	 * exercised, which is what a differential against a second implementation
	 * needs (notes/141). */
	{
		const char *df = getenv("ANERG_COVER_DUMP");
		if (df && *df) {
			FILE *fp = fopen(df, "w");
			if (fp) {
				for (i = 0; i < (0x40000u >> 2); i++)
					if (harness_cover_bits[i >> 3] & (1u << (i & 7)))
						fprintf(fp, "%05lx\n", i << 2);
				fclose(fp);
				fprintf(stderr, "[COVER] addresses written to %s\n", df);
			}
		}
	}

	/* ANERG_COVER_WANT=hex,hex,... -> did execution actually REACH these?
	 * Total coverage says the run went somewhere; this says it went to the
	 * place the experiment is about.  A negative result without this is not a
	 * result about that code. */
	want = getenv("ANERG_COVER_WANT");
	if (want && *want) {
		char buf[512], *tok, *sp2;
		size_t l = strlen(want);
		if (l >= sizeof buf) l = sizeof buf - 1;
		memcpy(buf, want, l); buf[l] = 0;
		for (tok = strtok_r(buf, ",", &sp2); tok; tok = strtok_r(NULL, ",", &sp2)) {
			unsigned long a = strtoul(tok, NULL, 16);
			unsigned idx = (unsigned)((a & 0x3ffff) >> 2);
			int hit = (harness_cover_bits[idx >> 3] >> (idx & 7)) & 1;
			fprintf(stderr, "[REACHED] %05lx %s\n", a, hit ? "YES" : "NO");
		}
	}
}

/* returns 1 if the instruction should be SKIPPED */
static int harness_fault_tick(void)
{
	int w;
	if (!hf_init) harness_fault_init();

	{ static int pm=-1; static long pw_lo=0, pw_hi=0;
	  if(pm<0){ const char*e=getenv("ANERG_PCMAP"); pm=(e&&*e=='1');
	            /* ANERG_PCWIN=lo:hi -- emit only for instruction indices in
	             * [lo,hi].  Without it a full run is ~21M lines. */
	            { const char*w=getenv("ANERG_PCWIN");
	              if(w){ pw_lo=strtol(w,NULL,0); const char*c=strchr(w,':');
	                     pw_hi=c?strtol(c+1,NULL,0):0; } } }
	  if(pm && (pw_hi==0 || (hf_count>=pw_lo && hf_count<=pw_hi)))
	      printf("%ld %05x\n", hf_count, ctx->pc); }

	/* harness: ANERG_HWTRACE=1 -> first-order Hamming-DISTANCE power model.
	 * This tick runs BEFORE instruction hf_count, so the register file still
	 * shows the result of instruction hf_count-1.  Diffing against the previous
	 * snapshot therefore gives the number of register-file bits that instruction
	 * TOGGLED -- the standard HD leakage model, and a far better proxy for real
	 * switching current than instruction class (notes/93 caveat 1).
	 * Emits: "<index-of-instruction-that-caused-it> <pc-of-that-instruction> <hd>" */
	{ static int hw=-1; static u32 (*prev)[4]; static u32 ppc; static long pidx;
	  if(hw<0){ const char*e=getenv("ANERG_HWTRACE"); hw=(e&&*e=='1');
	            if(hw){ prev=(u32(*)[4])calloc(128,sizeof(u32)*4);
	                    memcpy(prev, ctx->reg, sizeof(u32)*4*128);
	                    ppc=ctx->pc; pidx=hf_count; } }
	  if(hw&&prev){
	    if(hf_count>pidx){
	      unsigned r,w,hd=0;
	      for(r=0;r<128;r++) for(w=0;w<4;w++){
	        u32 x = prev[r][w] ^ ctx->reg[r][w];
	        if(x) hd += (unsigned)__builtin_popcount(x);
	      }
	      printf("%ld %05x %u\n", pidx, ppc, hd);
	      memcpy(prev, ctx->reg, sizeof(u32)*4*128);
	    }
	    ppc=ctx->pc; pidx=hf_count; } }

	/* harness: ANERG_COVER=1 -> cheap basic coverage.  A dynamic run that
	 * reports "nothing happened" is worthless unless you know it actually
	 * REACHED the code in question; notes/12's 900 fuzz cases all died at init
	 * and amounted to zero coverage. One bit per instruction slot, 8 KB. */
	{ static unsigned char *cov; static int cv=-1;
	  if(cv<0){ const char*e=getenv("ANERG_COVER"); cv=(e&&*e=='1');
	            if(cv){ cov=(unsigned char*)calloc(1,(0x40000>>2)/8+1);
	                    atexit(harness_cover_report); harness_cover_bits=cov; } }
	  if(cv&&cov){ unsigned idx=(ctx->pc&0x3ffff)>>2; cov[idx>>3]|=(unsigned char)(1u<<(idx&7)); } }

	/* harness: ANERG_WWATCH=lo:len -> report any change to an LS range */
	if (!ww_init) {
		const char *e = getenv("ANERG_WWATCH");
		ww_init = 1;
		if (e) { const char *c = strchr(e, ':');
			/* HEX, like every other ANERG_* address var (RDUMP, LSPEEK,
			 * POKEF).  This used to be base 0, so a bare "800" parsed as
			 * DECIMAL and silently watched the wrong address -- a watch
			 * that reports nothing looks exactly like "nothing writes it". */
			ww_lo = (u32)strtoul(e, NULL, 16);
			ww_len = c ? (u32)strtoul(c + 1, NULL, 16) : 16;
			if (ww_len > 128) ww_len = 128;
			if (ww_lo + ww_len <= 0x40000) memcpy(ww_prev, ctx->ls + ww_lo, ww_len);
			else ww_len = 0; }
	}
	if (ww_len && memcmp(ww_prev, ctx->ls + ww_lo, ww_len)) {
		u32 k; printf("[WW] i=%-9ld pc=%05x  %05x now ", hf_count, ctx->pc, ww_lo);
		for (k = 0; k < ww_len; k++) printf("%02x", ctx->ls[ww_lo + k]);
		printf("\n"); fflush(stdout);
		memcpy(ww_prev, ctx->ls + ww_lo, ww_len);
	}

	/* harness: ANERG_WATCH=pc[,pc...] -> print regs each time pc is reached */
	if (hf_nwatch < 0) {
		const char *w = getenv("ANERG_WATCH");
		hf_nwatch = 0;
		if (w) { char b[256], *t; strncpy(b, w, 255); b[255]=0;
			for (t = strtok(b, ","); t && hf_nwatch < 16; t = strtok(NULL, ","))
				hf_watch[hf_nwatch++] = (u32)strtoul(t, NULL, 16); }
	}
	{ static int _uinit = 0; if (!_uinit) { _uinit = 1; taint_universal_init(); } }
	{ extern unsigned char rrbw_map[128]; extern int rrbw_on;
	  if (rrbw_on < 0) {
		const char *e2 = getenv("ANERG_RREG");
		rrbw_on = (e2 && *e2 == '1');
		if (rrbw_on) { int q, w;
			for (q = 0; q < 128; q++) {
				if (q == 0 || q == 1) continue;          /* leave LR and SP */
				for (w = 0; w < 4; w++) ctx->reg[q][w] = 0xA0000000u | (u32)((q << 8) | w);
			}
			memset(rrbw_map, 0, sizeof rrbw_map);
		}
	  }
	}
	{ int wi; for (wi = 0; wi < hf_nwatch; wi++) if (ctx->pc == hf_watch[wi]) {
		printf("[W] i=%-9ld pc=%05x  $0=%08x $1=%08x $3=%08x $4=%08x $5=%08x $6=%08x $80=%08x  [sp+16]=%08x\n",
			hf_count, ctx->pc, ctx->reg[0][0], ctx->reg[1][0], ctx->reg[3][0],
			ctx->reg[4][0], ctx->reg[5][0], ctx->reg[6][0], ctx->reg[80][0],
			be32(ctx->ls + ((ctx->reg[1][0] + 16) & 0x3fffc)));
		fflush(stdout); } }

	if (hf_count > hf_maxi) {
		printf("[TIMEOUT] instrs=%ld pc=%05x\n", hf_count, ctx->pc);
		{ const char *lf = getenv("ANERG_LSDUMP");
		  if (lf) { FILE *o = fopen(lf, "wb");
		            if (o) { fwrite(ctx->ls, 1, 0x40000, o); fclose(o); } } }
		fflush(stdout);
		exit(0);
	}

	if (hf_stop_pc >= 0 && ctx->pc == (u32)hf_stop_pc) {
		if (++hf_hits < hf_nth) goto hf_no_stop;
		printf("[RESULT] r3=%08x instrs=%ld hit=%ld\n", ctx->reg[3][0], hf_count, hf_hits);
		{ const char *lf = getenv("ANERG_LSDUMP");
		  if (lf) { FILE *o = fopen(lf, "wb");
		            if (o) { fwrite(ctx->ls, 1, 0x40000, o); fclose(o); } } }
		{ const char *da=getenv("ANERG_DUMP");
		  if(da){ unsigned a=strtoul(da,NULL,0); int i;
		    printf("[DUMP] %05x:",a);
		    for(i=0;i<20;i++) printf("%02x", ctx->ls[a+i]);
		    printf("\n"); } }
		fflush(stdout);
		exit(0);
	}
hf_no_stop:

	/* ANERG_FAULT_PC="<pc>[:<nth>]" -- same fault menu, but triggered the Nth time
	   the SPU is about to execute <pc>.  A glitch lands on an instruction, not on
	   a global instruction index, so this is the realistic trigger. */
	{
		static int fp_init = 0; static u32 fppc = 0; static long fpn = 1, fphits = 0;
		if (!fp_init) {
			const char *e = getenv("ANERG_FAULT_PC");
			if (e) { fppc = (u32)strtoul(e, NULL, 16);
			         const char *c = strchr(e, ':'); if (c) fpn = strtol(c+1, NULL, 0); }
			fp_init = 1;
		}
		if (fppc && ctx->pc == fppc && ++fphits == fpn) hf_at = hf_count;
		if (getenv("ANERG_SITEIDX")) {
			if (ctx->pc == 0xc350 || ctx->pc == 0x1b3c || ctx->pc == 0x1b54 ||
			    ctx->pc == 0x0998 || ctx->pc == 0x385c)
				fprintf(stderr, "[SITE] pc=%05x instr_index=%ld\n", ctx->pc, hf_count);
		}
	}
	if (hf_at >= 0 && hf_count == hf_at) {
		switch (hf_type) {
		case 1: /* skip */
			hf_count++;
			ctx->pc += 4;
			return 1;
		case 2: /* zero whole register */
			for (w = 0; w < 4; w++) ctx->reg[hf_reg][w] = 0;
			break;
		case 3: /* single bit flip in preferred word */
			ctx->reg[hf_reg][0] ^= (1u << hf_bit);
			break;
		case 4: /* random corruption of preferred word */
			ctx->reg[hf_reg][0] = (u32)(hf_count * 2654435761u) ^ 0x5bd1e995u;
			break;
		case 5: /* set all ones */
			for (w = 0; w < 4; w++) ctx->reg[hf_reg][w] = 0xffffffffu;
			break;
		}
	}
	hf_count++;
	return 0;
}
/* ============================================================ */

u32 emulate(void)
{
	int res;

	u32 opc = ctx->pc;

	instr = be32(ctx->ls + ctx->pc);

	/* --- harness: call/branch trace, enabled with ANERG_TRACE=1 --- */
	{
		static int trace = -1;
		if (trace < 0) { const char *e = getenv("ANERG_TRACE"); trace = (e && *e=='1'); }
		if (trace) {
			/* brsl is a 9-bit opcode (bits 31..23) = 0x66; bi is 11-bit = 0x1a8 */
			if ((instr >> 23) == 0x66) {                          /* brsl */
				s32 i16 = (s32)((instr >> 7) & 0xffff);
				if (i16 & 0x8000) i16 -= 0x10000;
				fprintf(stderr,
				  "[call] %05x -> %05x  r3=%08x r4=%08x r5=%08x r6=%08x r7=%08x r8=%08x\n",
				  ctx->pc, (ctx->pc + (i16 << 2)) & 0x3ffff,
				  ctx->reg[3][0], ctx->reg[4][0], ctx->reg[5][0],
				  ctx->reg[6][0], ctx->reg[7][0], ctx->reg[8][0]);
			}
			/* bisl rt,ra -- INDIRECT call. Without this a vtable dispatch is
			 * invisible in the trace, which is exactly the case that matters
			 * when reversing these object-based modules. 11-bit opcode 0x1a9. */
			if ((instr >> 21) == 0x1a9) {
				u32 ra = (instr >> 7) & 0x7f;
				fprintf(stderr,
				  "[ICALL] %05x -> %05x  (via $%u)  r3=%08x r4=%08x r5=%08x r6=%08x\n",
				  ctx->pc, ctx->reg[ra][0] & 0x3fffc, ra,
				  ctx->reg[3][0], ctx->reg[4][0], ctx->reg[5][0], ctx->reg[6][0]);
			}
			if ((instr >> 21) == 0x1a8)                           /* bi */
				fprintf(stderr, "[ret ] %05x  r3=%08x\n", ctx->pc, ctx->reg[3][0]);
		}
	}

	/* --- harness: ANERG_LSPEEK="<pc>[#<n>[+]]:<addr>:<len>" -- print <len> bytes
	   of Local Store at <addr> when <pc> is reached.  Reads state at the moment
	   of use rather than relying on an end-of-run dump (the exit scrub zeroes it).

	   #<n>   fire on the Nth arrival instead of the first (1-based)
	   #<n>+  fire on the Nth and every arrival after it

	   Without this both hooks fired only on first arrival, and in appldr the
	   first arrival at the SHA-1 block loader is the REVOCATION LIST's hash --
	   15 million instructions before the section's, with different buffers.
	   Three probes in a row measured a pointer valid for the wrong pass
	   (notes/147).  These buffers are per-invocation; sampling the pass that
	   matters is what #N is for. --- */
	/* --- harness: ANERG_RDUMP="<pc>[#<n>[+]][:<regs>]" -- on the Nth arrival at <pc>,
	   print the named registers (comma-separated, default 3,4,5,6).  There was
	   no way to read an arbitrary register at a point: ANERG_STOP_PC prints only
	   r3 and ANERG_RREG POISONS registers rather than reading them.  Diagnosing
	   a loop's exit condition needs the counter and the limit (notes/139). --- */
	{
		static int rd_init = 0; static u32 rdpc = 0;
		static long rd_want = 1, rd_seen = 0; static int rd_rep = 0;
		static int rdregs[16], rdn = 0;
		if (!rd_init) {
			rd_init = 1;
			const char *e = getenv("ANERG_RDUMP");
			if (e) {
				char tmp[256]; strncpy(tmp, e, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
				char *colon = strchr(tmp, ':');
				if (colon) { *colon = 0;
					char *sv = NULL, *t = strtok_r(colon + 1, ",", &sv);
					while (t && rdn < 16) { rdregs[rdn++] = atoi(t); t = strtok_r(NULL, ",", &sv); }
				}
				char *hash = strchr(tmp, '#');
				if (hash) { *hash = 0;
					rd_want = strtol(hash + 1, NULL, 0);
					if (strchr(hash + 1, '+')) rd_rep = 1;
					if (rd_want < 1) rd_want = 1;
				}
				rdpc = (u32)strtoul(tmp, NULL, 16);
				if (!rdn) { rdregs[0]=3; rdregs[1]=4; rdregs[2]=5; rdregs[3]=6; rdn=4; }
			}
		}
		if (rdpc && ctx->pc == rdpc && ++rd_seen >= rd_want &&
		    (rd_rep || rd_seen == rd_want)) {
			/* print ALL FOUR words: SPU 64-bit values live in words 0-1, and
			   printing word 0 alone made a doubleword limit of 0x140 look like
			   ZERO (notes/139).  Never show a partial register. */
			fprintf(stderr, "[RDUMP] pc=%05x #%ld i=%ld", rdpc, rd_seen, hf_count);
			for (int i = 0; i < rdn; i++) {
				int q = rdregs[i];
				fprintf(stderr, " $%d=%08x_%08x_%08x_%08x", q,
				        ctx->reg[q][0], ctx->reg[q][1], ctx->reg[q][2], ctx->reg[q][3]);
			}
			fprintf(stderr, "\n");
		}
	}
	{
		static int pk2_init = 0; static u32 p2pc=0, p2ad=0, p2ln=0;
		static long p2_want = 1, p2_seen = 0; static int p2_rep = 0;
		if (!pk2_init) { const char *e = getenv("ANERG_LSPEEK"); pk2_init = 1;
			if (e) {
				char tmp[256]; strncpy(tmp, e, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
				char *hash = strchr(tmp, '#');
				if (hash) {
					char *colon = strchr(hash, ':');
					*hash = 0;
					p2_want = strtol(hash + 1, NULL, 0);
					if (memchr(hash + 1, '+', colon ? (size_t)(colon - hash - 1) : strlen(hash + 1)))
						p2_rep = 1;
					if (p2_want < 1) p2_want = 1;
					p2pc = (u32)strtoul(tmp, NULL, 16);
					if (colon) sscanf(colon + 1, "%x:%x", &p2ad, &p2ln);
				} else sscanf(tmp, "%x:%x:%x", &p2pc, &p2ad, &p2ln);
			}
		}
		if (p2ln && ctx->pc == p2pc && ++p2_seen >= p2_want &&
		    (p2_rep || p2_seen == p2_want)) {
			u32 i;
			fprintf(stderr, "[LSPEEK] pc=%05x #%ld i=%ld LS[%05x..%05x] ",
			        p2pc, p2_seen, hf_count, p2ad, p2ad+p2ln);
			for (i = 0; i < p2ln; i++) fprintf(stderr, "%02x", ctx->ls[(p2ad+i) & 0x3ffff]);
			fprintf(stderr, "\n");
		}
	}

	/* --- harness: ANERG_TAINTMAP=1 -- at exit, print the contiguous LS ranges that
	   carry taint.  Used to locate where a given FILE region ends up in Local Store
	   after the loader copies/parses it. --- */
	{
		static int tm_done = 0;
		if (!tm_done && getenv("ANERG_TAINTMAP") && hf_count > 0 && (hf_count % 5000000) == 0) {
			u32 i = 0; tm_done = 0;
			fprintf(stderr, "[TMAP] tainted LS ranges at instr %ld:\n", hf_count);
			while (i < 0x40000) {
				if (ls_taint[i]) { u32 st = i; while (i < 0x40000 && ls_taint[i]) i++;
				                   fprintf(stderr, "         %05x..%05x  (%u bytes)\n", st, i, i-st); }
				else i++;
			}
		}
	}

	/* --- harness: ANERG_RTWATCH="<reg>"  Report every change of reg_taint[<reg>],
	   with the PC that caused it.  Written to find where taint dies in a chain. --- */
	{
		static int rw_init = 0, rw_reg = -1; static u32 rw_last = 0; static int rw_have = 0;
		if (!rw_init) { const char *e = getenv("ANERG_RTWATCH");
		                if (e) rw_reg = (int)strtol(e, NULL, 0); rw_init = 1; }
		if (rw_reg >= 0) {
			u32 cur = taint_reg_any(rw_reg);
			if (!rw_have) { rw_last = cur; rw_have = 1; }
			else if (cur != rw_last) {
				fprintf(stderr, "[RT] r%d taint %08x -> %08x (before pc=%05x)\n",
				        rw_reg, rw_last, cur, ctx->pc);
				rw_last = cur;
			}
		}
	}

	/* --- harness: ANERG_RETAINT="<pc>:<lo>:<hi>"  On first arrival at <pc>, mark
	   LS [lo,hi) as tainted.  Needed because metldr's metadata is AES-CTR
	   ciphertext on the wire: byte-granular taint from the EA cannot survive the
	   block cipher, so the fields that actually drive the MFC (section offsets,
	   sizes, load addresses) are untainted by the time they are used.  Re-tainting
	   the DECRYPTED buffer is the only way to ask whether attacker-chosen metadata
	   steers a sink. --- */
	{
		static int rt_init = 0, rt_fired = 0; static u32 rtpc = 0, rtlo = 0, rthi = 0;
		if (!rt_init) {
			const char *e = getenv("ANERG_RETAINT");
			if (e) sscanf(e, "%x:%x:%x", &rtpc, &rtlo, &rthi);
			rt_init = 1;
		}
		if (!rt_fired && rthi > rtlo && ctx->pc == rtpc) {
			u32 _i;
			for (_i = rtlo; _i < rthi && _i < 0x40000; _i++) ls_taint[_i] = 0x05000000u | (_i + 1);
			taint_on = 1; rt_fired = 1;
			fprintf(stderr, "[RETAINT] pc=%05x tainted LS %05x..%05x (%u bytes)\n",
			        rtpc, rtlo, rthi, rthi - rtlo);
		}
	}

	/* --- harness: ANERG_FWATCH="<lsaddr>"  Report every CHANGE of the 32-bit word
	   at <lsaddr>, with the PC that produced it.  Word-precise, unlike WPROT which
	   is quadword-granular. --- */
	{
		static int fw_init = 0; static u32 fwad = 0, fwlast = 0; static int fwhave = 0;
		if (!fw_init) {
			const char *e = getenv("ANERG_FWATCH");
			if (e) sscanf(e, "%x", &fwad);
			fw_init = 1;
		}
		if (fw_init && getenv("ANERG_FWATCH")) {
			u32 cur = be32(ctx->ls + (fwad & 0x3fffc));
			if (!fwhave) { fwlast = cur; fwhave = 1; }
			else if (cur != fwlast) {
				fprintf(stderr, "[FW] LS[%05x] %08x -> %08x (pc=%05x)\n",
				        fwad, fwlast, cur, ctx->pc);
				fwlast = cur;
			}
		}
	}

	/* --- harness: ANERG_POKE="<pc>:<lsaddr>:<word>"  On first arrival at <pc>,
	   store <word> big-endian at LS <lsaddr>.  Used to test whether flipping the
	   writer object's vtable pointer (0xc868 -> 0xc848) redirects metldr's section
	   output from Local Store to a host-memory DMA PUT. --- */
	/* --- harness: ANERG_POKEF="<pc>:<lsaddr>:<file>"  On first arrival at <pc>,
	   load <file> into LS at <lsaddr>.  ANERG_POKE writes a single word, which is
	   not enough when a structure has to be planted AFTER the target has cleared
	   its own BSS -- see notes/96, isoldr zeroes the context at 0x38b30 during
	   init, so a -L preload is wiped before it can be read. --- */
	{
		/* ANERG_POKEF="<pc>:<lsaddr>:<file>[,<pc>:<lsaddr>:<file>...]"
		   Multiple injections, comma-separated, each firing once on first
		   arrival at its own pc.  isoldr needs TWO decrypted metadata blocks
		   (the SRVK's and the module's) at different PCs -- see notes/139.

		   <lsaddr> may instead be "@<reg>", meaning: take the destination from
		   the preferred slot of register <reg> at that pc.  A hardcoded 0x3a520
		   was correct for sv_iso and WRONG for spp_verifier, whose metadata
		   buffer sits at 0x3a560 -- and the resulting -1 from 0x35360 looked
		   exactly like isoldr rejecting the module (notes/140). */
		enum { PF_MAX = 8 };
		static int pf_init = 0;
		static u32 pfpc[PF_MAX], pfad[PF_MAX]; static int pffired[PF_MAX];
		static int pfreg[PF_MAX];
		static unsigned char *pfbuf[PF_MAX]; static long pflen[PF_MAX];
		static int pfn = 0;
		if (!pf_init) {
			const char *e = getenv("ANERG_POKEF");
			pf_init = 1;
			if (e) {
				char tmp[2048]; strncpy(tmp, e, sizeof tmp - 1); tmp[sizeof tmp - 1] = 0;
				char *save = NULL, *tok = strtok_r(tmp, ",", &save);
				while (tok && pfn < PF_MAX) {
					char path[512]; path[0] = 0;
					u32 a = 0, b = 0; int reg = -1;
					int ok = (sscanf(tok, "%x:@%d:%511s", &a, &reg, path) == 3);
					if (!ok) { reg = -1; ok = (sscanf(tok, "%x:%x:%511s", &a, &b, path) == 3); }
					if (ok) {
						FILE *fp = fopen(path, "rb");
						if (fp) {
							fseek(fp, 0, SEEK_END); pflen[pfn] = ftell(fp); fseek(fp, 0, SEEK_SET);
							pfbuf[pfn] = (unsigned char *)malloc(pflen[pfn] ? pflen[pfn] : 1);
							if (pfbuf[pfn] && fread(pfbuf[pfn], 1, pflen[pfn], fp) != (size_t)pflen[pfn])
								pflen[pfn] = 0;
							fclose(fp);
							pfpc[pfn] = a; pfad[pfn] = b; pfreg[pfn] = reg;
							pffired[pfn] = 0; pfn++;
						}
					}
					tok = strtok_r(NULL, ",", &save);
				}
			}
		}
		for (int pi = 0; pi < pfn; pi++) {
			if (!pffired[pi] && pflen[pi] && ctx->pc == pfpc[pi]) {
				long n = pflen[pi];
				u32 dst = pfreg[pi] >= 0 ? (ctx->reg[pfreg[pi]][0] & 0x3ffff)
				                         : pfad[pi];
				if (dst + n > 0x40000) n = 0x40000 - dst;
				memcpy(ctx->ls + dst, pfbuf[pi], n);
				pffired[pi] = 1;
				fprintf(stderr, "[POKEF] pc=%05x LS[%05x]%s <- %ld bytes\n",
				        pfpc[pi], dst, pfreg[pi] >= 0 ? " (from $r)" : "", n);
			}
		}
	}

	{
		static int pk_init = 0, pk_fired = 0; static u32 pkpc=0, pkad=0, pkvl=0;
		if (!pk_init) {
			const char *e = getenv("ANERG_POKE");
			if (e) sscanf(e, "%x:%x:%x", &pkpc, &pkad, &pkvl);
			pk_init = 1;
		}
		if (!pk_fired && pkad && ctx->pc == pkpc) {
			u32 old = be32(ctx->ls + (pkad & 0x3fffc));
			wbe32(ctx->ls + (pkad & 0x3fffc), pkvl);
			pk_fired = 1;
			fprintf(stderr, "[POKE] pc=%05x LS[%05x] %08x -> %08x\n", pkpc, pkad, old, pkvl);
		}
	}

	/* --- harness: ANERG_VTRACE=1 traces the stream-object vtable dispatches.
	   At 0x29e8 / 0x3050 the object pointer is in $81 and the loaded vtable base
	   in $17 / $16 respectively.  Prints where obj[0] lives so the writable
	   address of the vtable pointer can be read off, not guessed. --- */
	{
		static int vt = -1;
		if (vt < 0) { const char *e = getenv("ANERG_VTRACE"); vt = (e && *e=='1'); }
		if (vt) {
			if (ctx->pc == 0x29e8)
				fprintf(stderr, "[VT] pc=29e8 slot2 obj=%05x vtbl=%05x\n",
				        ctx->reg[81][0] & 0x3ffff, ctx->reg[17][0]);
			else if (ctx->pc == 0x3050)
			{	u32 _o = ctx->reg[81][0] & 0x3ffff, _k;
				fprintf(stderr, "[VT] pc=3050 slot3 obj=%05x vtbl=%05x fields:",
				        _o, ctx->reg[16][0]);
				for (_k = 0; _k < 8; _k++)
					fprintf(stderr, " +%02x=%08x", _k*4, be32(ctx->ls + ((_o + _k*4) & 0x3fffc)));
				fprintf(stderr, "\n"); }
		}
	}

	/* --- TAINT-SINK checks: does tainted data steer anything that matters? ---
	   ANERG_TAINT_NOBR=1 disables the branch-condition sink, which saturates when
	   tainting a parsed header (a parser's job IS to branch on its input). */
	if (taint_on > 0) {
		static int nobr = -1;
		u32 _op11 = instr >> 21, _op9 = instr >> 23, _op8 = instr >> 24;
		u32 _ra = (instr >> 7) & 0x7f, _rb = (instr >> 14) & 0x7f, _rt = instr & 0x7f;
		if (nobr < 0) { const char *e3 = getenv("ANERG_TAINT_NOBR"); nobr = (e3 && *e3=='1'); }

		if ((_op11 == 0x1a8 || _op11 == 0x1a9) && taint_word0(_ra))          /* bi / bisl */
			fprintf(stderr, "[SINK1-EXEC] pc=%05x r%u target=%05x origin=%05x %s\n",
			        ctx->pc, _ra, ctx->reg[_ra][0] & 0x3ffff, taint_word0(_ra)-1,
			        ((ctx->reg[_ra][0] & 0x3ffff) < 0xec50) ? "(inside)" : "(OUTSIDE)");

		if (_op11 == 0x10d) {                                                  /* wrch */
			u32 _ch = _ra;
			if (_ch >= 16 && _ch <= 21 && taint_word0(_rt))
			{	char _l[17]; int _j;
				for (_j=0;_j<16;_j++) _l[_j] = reg_taint[_rt][_j] ? 'T' : '.';
				_l[16]=0;
				fprintf(stderr, "[SINK2-DMA] ch%u pc=%05x origin=%05x val=%08x lanes=%s\n",
				        _ch, ctx->pc, taint_word0(_rt)-1, ctx->reg[_rt][0], _l); }
			if ((_ch == 28 || _ch == 30) && taint_word0(_rt))                /* outbound mailbox */
				fprintf(stderr, "[SINK6-MBOX] ch%u pc=%05x origin=%05x\n", _ch, ctx->pc, taint_word0(_rt)-1);
		}

		/* Sink 5: local-store ADDRESS operands.  No MMU here, so a tainted base or
		   index in lqx/stqx/lqd/stqd is an arbitrary read/write inside the 256 KB. */
		if ((_op11 == 0x1c4 || _op11 == 0x144) &&                              /* lqx / stqx */
		    (taint_word0(_ra) || taint_word0(_rb)))
			fprintf(stderr, "[SINK5-LSADDR] %s pc=%05x origin=%05x addr=%05x\n",
			        _op11 == 0x144 ? "stqx" : "lqx", ctx->pc,
			        (taint_word0(_ra)?taint_word0(_ra):taint_word0(_rb))-1,
			        (ctx->reg[_ra][0] + ctx->reg[_rb][0]) & 0x3ffff);
		if ((_op8 == 0x34 || _op8 == 0x24) && taint_word0(_ra))              /* lqd / stqd */
			fprintf(stderr, "[SINK5-LSADDR] %s pc=%05x origin=%05x addr=%05x\n",
			        _op8 == 0x24 ? "stqd" : "lqd", ctx->pc, taint_word0(_ra)-1,
			        ctx->reg[_ra][0] & 0x3ffff);

		if (!nobr && (_op9 == 0x40 || _op9 == 0x41 || _op9 == 0x42 || _op9 == 0x43)
		    && taint_reg_any(_rt))
			fprintf(stderr, "[SINK3-BRANCH] branch condition tainted pc=%05x r%u\n", ctx->pc, _rt);
	}

#ifdef DEBUG_INSTR
	dbgprintf("%05x: %08x ", ctx->pc, instr);
#endif

	if (gdb_bp_x(ctx->pc)) {
#ifdef DEBUG_GDB
		printf("------------------------------------------ break %08x\n", ctx->pc);
#endif
		ctx->paused = 1;
		gdb_signal(SIGTRAP);
		return 0;
	}

#ifdef DEBUG_TRACE
	dbgprintf("%05x: %08x (r1=%08x) ", ctx->pc, instr, ctx->reg[1][0]);
#endif

	if (harness_fault_tick())
		return 0;

	res = emulate_instr();
	if (res != 0)
		return res;

#ifdef DEBUG_TRACE
	dbgprintf("%05x: ", ctx->pc);
	dbgprintf("rt:\t%08x %08x %08x %08x ",
			rtw[0],
			rtw[1],
			rtw[2],
			rtw[3]
			);
	dbgprintf("ra:\t%08x %08x %08x %08x ",
			raw[0],
			raw[1],
			raw[2],
			raw[3]
			);
	if ((instr_tbl[op].type == SPU_INSTR_RR) || (instr_tbl[op].type == SPU_INSTR_RRR))
	{
		dbgprintf("rb:\t%08x %08x %08x %08x ",
				rbw[0],
				rbw[1],
				rbw[2],
				rbw[3]
				);
	}
	if (instr_tbl[op].type == SPU_INSTR_RRR)
	{
		dbgprintf("rc:\t%08x %08x %08x %08x",
				rcw[0],
				rcw[1],
				rcw[2],
				rcw[3]
				);
	}
	printf("\n");
#endif

#ifdef DEBUG_INSTR
	if (ctx->pc != opc)
		dbgprintf("...\n");
#endif

	ctx->pc += 4;
	ctx->pc &= LSLR;

	if ((ctx->pc & 3) != 0)
		fail("pc is not aligned: %08x", ctx->pc);

//	dbgprintf("\n\n", count);
	return 0;
}
