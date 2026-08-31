// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "types.h"
#include "emulate.h"
#include "main.h"
#include "helper.h"

#define PROV_T0_SRAM 0x01000000u
#define PROV_T0_REG  0x02000000u
#define PROV_CHAN    0x03000000u
#define PROV_DMA     0x04000000u

#ifndef DEBUG_INSTR_MEM
#define vdbgprintf(...)
#else
#include <stdio.h>
#include <stdlib.h>

#define vdbgprintf printf
#endif

/* --- harness: read-before-write detector.  ANERG_RBW=<image_end_hex> marks
   [0, image_end) as initialised (the loader image itself) and then flags any LOAD
   from a quadword never previously STORED.  This generalises a one-off finding
   (a 64-byte window read but never written) into a whole-LS sweep. --- */
static unsigned char rbw_map[0x40000 / 16];
static int   rbw_on   = -1;
static u32   rbw_end  = 0;
/* ===== byte-granular taint tracker =====================================
   Motivation: this architecture has no sub-quadword store, so writing 4 bytes
   is load / shufb / store.  A word-granular tracker loses the untouched lanes,
   which is exactly where uninitialised bytes survive.  So: one shadow byte per
   LS byte, and 16 shadow bytes per register.
     ANERG_TAINT=lo:hi   mark that LS range tainted at start
   Sinks reported: indirect branch target, branch condition, MFC command regs. */
u32 ls_taint[0x40000];
u32 *ea_taint = 0;            /* attacker-supplied host memory, tainted by ANERG_TAINT_EA */
u32 ea_taint_len = 0;
u32 reg_taint[128][16];
int taint_on = -1;
int taint_rt_set = 0;            /* a load already set rt's taint this instruction */

void taint_ea_init(u32 ea_size)
{
	const char *e = getenv("ANERG_TAINT_EA");
	u32 lo = 0, hi = 0, i;
	if (!e || ea_taint) return;
	ea_taint = (u32 *)calloc(ea_size, sizeof(u32));
	ea_taint_len = ea_size;
	if (ea_taint && sscanf(e, "%x:%x", &lo, &hi) == 2 && hi > lo) {
		for (i = lo; i < hi && i < ea_size; i++) ea_taint[i] = 0x800000u | (i + 1);  /* EA origin */
		taint_on = 1;
	}
}

void taint_dma_in(u32 lsa, u32 ea, u32 sz)   /* propagate taint EA -> LS across a DMA GET */
{
	u32 i;
	if (taint_universal) {                    /* boundary 3: host data, always tainted */
		for (i = 0; i < sz; i++) ls_taint[(lsa + i) & 0x3ffff] = PROV_DMA | ((ea + i) & 0xffffff);
		return;
	}
	if (taint_on <= 0 || !ea_taint) return;
	for (i = 0; i < sz; i++)
		ls_taint[(lsa + i) & 0x3ffff] = (ea + i < ea_taint_len) ? ea_taint[ea + i] : 0;
}

/* ===== Universal Boundary Taint ==========================================
   Instead of hand-painting regions we suspect, let the architecture enumerate
   the inputs.  An isolated in-order core with no interrupts can be influenced
   ONLY by data crossing three boundaries:
       1. state present at T=0 (local store + registers)
       2. channel reads  (mailbox, tag status, DECREMENTER, ...)
       3. DMA GET completions
   Taint all three automatically with distinct provenance namespaces.  A clean
   run then bounds the whole surface, not just the parts we thought to test. */
int taint_universal = 0;

void taint_universal_init(void)
{
	u32 i; int r, k;
	const char *e = getenv("ANERG_TAINT_ALL");
	u32 img_end;
	if (!e) return;
	/* The loader's OWN IMAGE occupies local store at T=0.  Tainting it marks the
	   loader's own constants and function-pointer tables as attacker input, which
	   both saturates the address sink and manufactures false dispatch hits.
	   ANERG_TAINT_ALL=<image_end_hex> taints only memory OUTSIDE the image. */
	img_end = (u32)strtoul(e, NULL, 16);
	if (img_end == 1) img_end = 0;              /* legacy "=1" means taint everything */
	taint_universal = 1; taint_on = 1;
	for (i = img_end; i < 0x40000; i++) ls_taint[i] = PROV_T0_SRAM | i;
	for (r = 0; r < 128; r++) for (k = 0; k < 16; k++)
		reg_taint[r][k] = PROV_T0_REG | (u32)((r << 4) | k);
}

void taint_chan(int ch, int reg)          /* boundary 2: any channel read */
{
	int k;
	if (!taint_universal) return;
	for (k = 0; k < 16; k++) reg_taint[reg][k] = PROV_CHAN | (u32)ch;
	taint_rt_set = 1;
}

void taint_init(void)
{
	const char *e = getenv("ANERG_TAINT");
	if (taint_on == 1) return;        /* EA taint already armed it -- do not clear */
	taint_on = 0;
	if (e) {
		u32 lo = 0, hi = 0, i;
		if (sscanf(e, "%x:%x", &lo, &hi) == 2 && hi > lo) {
			for (i = lo; i < hi && i < 0x40000; i++) ls_taint[i] = i + 1;   /* provenance */
			taint_on = 1;
		}
	}
}
u32 taint_reg_any(u32 r) { int i; for (i=0;i<16;i++) if (reg_taint[r][i]) return reg_taint[r][i]; return 0; }

void rbw_mark_range(u32 lo, u32 len)   /* DMA writes bypass reg2ls; mark them too */
{
	u32 i;
	if (rbw_on <= 0) return;
	for (i = lo & ~15u; i < lo + len && i < 0x40000; i += 16) rbw_map[i >> 4] = 1;
}

/* --- harness: REGISTER read-before-write.  ANERG_RREG=1 seeds every GPR with a
   distinct magic (0xA00000NN in each word) and flags the first READ of any register
   not yet written by the running code.  Answers: does the loader inherit state? --- */
unsigned char rrbw_map[128];
int rrbw_on = -1;

static void rbw_init(void)
{
	const char *e = getenv("ANERG_RBW");
	rbw_on = (e != NULL);
	if (rbw_on) {
		u32 i;
		rbw_end = (u32)strtoul(e, NULL, 16);
		for (i = 0; i < rbw_end && i < 0x40000; i += 16) rbw_map[i >> 4] = 1;
	}
}

void reg2ls(u32 r, u32 addr)
{
	addr &= LSLR & 0xfffffff0;
	if (taint_on < 0) taint_init();
	if (taint_on) { int _i; for (_i=0;_i<16;_i++) ls_taint[(addr+_i) & 0x3ffff] = reg_taint[r][_i]; }
	if (rbw_on < 0) rbw_init();
	if (rbw_on) rbw_map[addr >> 4] = 1;
		vdbgprintf("  LS STORE: %05x: %08x %08x %08x %08x\n", addr, ctx->reg[r][0], ctx->reg[r][1], ctx->reg[r][2], ctx->reg[r][3]);
	/* --- harness: write-protect watch.  ANERG_WPROT=lo:hi (hex) flags any
	   store landing in [lo,hi).  A store into the executable section is the
	   signal that a pointer was steered, which is what we actually hunt. --- */
	{
		static int inited = 0; static u32 wlo = 0, whi = 0;
		if (!inited) {
			const char *e = getenv("ANERG_WPROT");
			if (e) sscanf(e, "%x:%x", &wlo, &whi);
			inited = 1;
		}
		if (whi > wlo && addr >= wlo && addr < whi)
			fprintf(stderr, "[WPROT] store to %05x (pc=%05x)\n", addr, ctx->pc);
	}

	wbe32(ctx->ls + addr, ctx->reg[r][0]);
	wbe32(ctx->ls + addr + 4, ctx->reg[r][1]);
	wbe32(ctx->ls + addr + 8, ctx->reg[r][2]);
	wbe32(ctx->ls + addr + 12, ctx->reg[r][3]);
}

void ls2reg(u32 r, u32 addr)
{
	addr &= LSLR & 0xfffffff0;
	if (rbw_on < 0) rbw_init();
	if (rbw_on && !rbw_map[addr >> 4]) {
		rbw_map[addr >> 4] = 2;          /* report each address once */
		fprintf(stderr, "[RBW] uninit read %05x (pc=%05x)\n", addr, ctx->pc);
	}
	/* --- harness: read-poison watch.  ANERG_RPOIS=lo:hi (hex) flags any LOAD
	   from [lo,hi).  Used to test whether a parser consumes bytes beyond the
	   length it was actually given (stale-buffer question). --- */
	{
		static int rinit = 0; static u32 rlo = 0, rhi = 0;
		if (!rinit) {
			const char *e = getenv("ANERG_RPOIS");
			if (e) sscanf(e, "%x:%x", &rlo, &rhi);
			rinit = 1;
		}
		if (rhi > rlo && addr + 16 > rlo && addr < rhi)
			fprintf(stderr, "[RPOIS] load from %05x (pc=%05x)\n", addr, ctx->pc);
	}

	if (taint_on < 0) taint_init();
	if (taint_on) { int _i, _any = 0;
	                for (_i=0;_i<16;_i++) { reg_taint[r][_i] = ls_taint[(addr+_i) & 0x3ffff];
	                                        if (reg_taint[r][_i]) _any = 1; }
	                taint_rt_set = 1;
	                /* LR-TAINT: a tainted value loaded into the LINK REGISTER is either a
	                   harmless artefact or a return-address overwrite.  Report the source
	                   address so the origin can be traced rather than assumed. */
	                if (r == 0 && _any)
	                    { char _m[17]; int _j;
	                      for (_j=0;_j<16;_j++) _m[_j] = ls_taint[(addr+_j)&0x3ffff] ? 'T' : '.';
	                      _m[16]=0;
	                      fprintf(stderr, "[LR-TAINT] from %05x (pc=%05x) value=%08x lanes=%s\n",
	                              addr, ctx->pc, be32(ctx->ls + addr), _m); } }
	ctx->reg[r][0] = be32(ctx->ls + addr);
	ctx->reg[r][1] = be32(ctx->ls + addr + 4);
	ctx->reg[r][2] = be32(ctx->ls + addr + 8);
	ctx->reg[r][3] = be32(ctx->ls + addr + 12);
		vdbgprintf("  LS LOAD: %05x: %08x %08x %08x %08x\n", addr, ctx->reg[r][0], ctx->reg[r][1], ctx->reg[r][2], ctx->reg[r][3]);
}

void reg_to_byte(u8 *d, int r)
{
	int i, j;
	for (i = 0; i < 4; ++i)
		for (j = 0; j < 4; ++j)
			*d++ = ctx->reg[r][i] >> (24 - j*8);
}

void byte_to_reg(int r, const u8 *d)
{
	int i, j;
	for (i = 0; i < 4; ++i)
	{
		ctx->reg[r][i] = 0;
		for (j = 0; j < 4; ++j)
			ctx->reg[r][i] |= *d++ << (24 - j*8);
	}
}

void reg_to_half(u16 *d, int r)
{
	int i, j;
	for (i = 0; i < 4; ++i)
		for (j = 0; j < 2; ++j)
		{
			*d++ = ctx->reg[r][i] >> (16 - j*16);
		}
}

void half_to_reg(int r, const u16 *d)
{
	int i, j;
	for (i = 0; i < 4; ++i)
	{
		ctx->reg[r][i] = 0;
		for (j = 0; j < 2; ++j)
			ctx->reg[r][i] |= *d++ << (16 - j*16);
	}
}

void reg_to_Bits(u1 *d, int r)
{
	int i, j;
	for (i = 0; i < 4; ++i)
		for (j = 0; j < 32; ++j)
		{
			*d++ = (ctx->reg[r][i] >> (31 - j)) & 1;
		}
}

void Bits_to_reg(int r, const u1 *d)
{
	int i, j;
	for (i = 0; i < 4; ++i)
	{
		ctx->reg[r][i] = 0;
		for (j = 0; j < 32; ++j)
			ctx->reg[r][i] |= *d++ << (31 - j);
	}
}
