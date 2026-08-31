// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#include "config.h"
#include "types.h"
#include "emulate.h"
#include "main.h"
#include "helper.h"
#include "channel.h"
#include "gdb.h"
#include <stdio.h>

#ifndef DEBUG_INSTR
#define vdbgprintf(...)
#else
#define vdbgprintf printf
#endif

int instr_lqd(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);i10 <<= 4;
	/* show disassembly*/
	vdbgprintf("lqd $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		u32 addr = i10 + raw[0];

	if (gdb_bp_r(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		ls2reg(rt, i10 + raw[0]);

	/* post transform */
	
	return stop;
}
int instr_lqx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("lqx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		u32 addr = raw[0] + rbw[0];

	if (gdb_bp_r(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		ls2reg(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_lqa(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("lqa $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 addr = i16;

	if (gdb_bp_r(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		ls2reg(rt, i16);

	/* post transform */
	
	return stop;
}
int instr_lqr(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("lqr $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 addr = ctx->pc + i16;

	if (gdb_bp_r(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		ls2reg(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_stqd(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);i10 <<= 4;
	/* show disassembly*/
	vdbgprintf("stqd $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		u32 addr = i10 + raw[0];

	if (gdb_bp_w(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		reg2ls(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_stqx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("stqx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		u32 addr = raw[0] + rbw[0];

	if (gdb_bp_w(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		reg2ls(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_stqa(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("stqa $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 addr = i16;

	if (gdb_bp_w(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		reg2ls(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_stqr(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("stqr $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 addr = ctx->pc + i16;

	if (gdb_bp_w(addr) || gdb_bp_a(addr))
		stop = 2;
	else
		reg2ls(rt, addr);

	/* post transform */
	
	return stop;
}
int instr_cbd(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	i7 = se7(i7);u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("cbd $r%d,$r%d,%d\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int t = (raw[0] + i7) & 0xF;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = ((i == t) ? 0x03 : (i|0x10));

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_cbx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("cbx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int t = (raw[0] + rbw[0]) & 0xF;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = ((i == t) ? 0x03 : (i|0x10));

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_chd(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	i7 = se7(i7);u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("chd $r%d,$r%d,%d\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int t = raw[0] + i7;

	t >>= 1;
	t &= 7;
	
	int i;
	for (i = 0; i < 8; ++i)
		rth[i] = ((i == t) ? 0x0203 : (i * 2 * 0x0101 + 0x1011));

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_chx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("chx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int t = raw[0] + rbw[0];

	t >>= 1;
	t &= 7;
	
	int i;
	for (i = 0; i < 8; ++i)
		rth[i] = ((i == t) ? 0x0203 : (i * 2 * 0x0101 + 0x1011));

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_cwd(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cwd $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int t;

	t = raw[0] + i7;
	t >>= 2;
	t &= 3;

	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (i == t) ? 0x00010203 : (0x01010101 * (i * 4) + 0x10111213);

	/* post transform */
	
	return stop;
}
int instr_cwx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cwx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int t;

	t = raw[0] + rbw[0];
	t >>= 2;
	t &= 3;

	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (i == t) ? 0x00010203 : (0x01010101 * (i * 4) + 0x10111213);

	/* post transform */
	
	return stop;
}
int instr_cdd(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	i7 = se7(i7);
	/* show disassembly*/
	vdbgprintf("cdd $r%d,$r%d,%d\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int t;

	t = raw[0] + i7;
	t >>= 2;
	t &= 2;

	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (i == t) ? 0x00010203 : (i == (t + 1)) ? 0x04050607 : (0x01010101 * (i * 4) + 0x10111213);

	/* post transform */
	
	return stop;
}
int instr_cdx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cdx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int t;

	t = raw[0] + rbw[0];
	t >>= 2;
	t &= 2;

	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (i == t) ? 0x00010203 : (i == (t + 1)) ? 0x04050607 : (0x01010101 * (i * 4) + 0x10111213);

	/* post transform */
	
	return stop;
}
int instr_ilh(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("ilh $r%d,0x%x\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 s;

	s = (i16 << 16) | i16;
	
	rtw[0] = s;
	rtw[1] = s;
	rtw[2] = s;
	rtw[3] = s;

	/* post transform */
	
	return stop;
}
int instr_ilhu(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("ilhu $r%d,0x%x\n", rt,i16);
	/* optional trapping */
	
	/* body */
		u32 s;

	s = (i16 << 16);
	
	rtw[0] = s;
	rtw[1] = s;
	rtw[2] = s;
	rtw[3] = s;

	/* post transform */
	
	return stop;
}
int instr_il(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);
	/* show disassembly*/
	vdbgprintf("il $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		rtw[0] = i16;
	rtw[1] = i16;
	rtw[2] = i16;
	rtw[3] = i16;

	/* post transform */
	
	return stop;
}
int instr_ila(u32 rt, u32 i18)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i18; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("ila $r%d,0x%x\n", rt,i18);
	/* optional trapping */
	
	/* body */
		
	rtw[0] = i18;
	rtw[1] = i18;
	rtw[2] = i18;
	rtw[3] = i18;

	/* post transform */
	
	return stop;
}
int instr_iohl(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("iohl $r%d,0x%x\n", rt,i16);
	/* optional trapping */
	
	/* body */
	
	rtw[0] |= i16; 
	rtw[1] |= i16; 
	rtw[2] |= i16; 
	rtw[3] |= i16; 

	/* post transform */
	
	return stop;
}
int instr_fsmbi(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);
	/* show disassembly*/
	vdbgprintf("fsmbi $r%d,0x%x\n", rt,i16);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = (i16 & (1<<(15-i))) ? ~0 : 0;

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_heqi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("heqi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		if (i10 == rawp)
		stop = 1;

	/* post transform */
	
	return stop;
}
int instr_stop(u32 opcode)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("stop %08x\n", opcode);
	/* optional trapping */
	if (ctx->trap) return 1;
	/* body */
		if ((opcode & 0xFF00) == 0x2100)
	{
		u32 sel = be32(ctx->ls + ctx->pc + 4);
		u32 arg = sel & 0xFFFFFF;
		sel >>= 24;

		printf("CELL SDK __send_to_ppe(0x%04x, 0x%02x, 0x%06x);\n", opcode & 0xFF, sel, arg);
	} else
		printf("####### stop instruction reached: %08x\n", opcode);

	/* post transform */
	
	return stop;
}
int instr_stopd(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("stopd $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	if (ctx->trap) return 1;
	/* body */
		printf("####### stopd instruction reached\n");
	printf("ra: %08x %08x %08x %08x\n",
			raw[0],
			raw[1],
			raw[2],
			raw[3]);
	printf("rb: %08x %08x %08x %08x\n",
			rbw[0],
			rbw[1],
			rbw[2],
			rbw[3]);
	printf("rc: %08x %08x %08x %08x\n",
			rtw[0],
			rtw[1],
			rtw[2],
			rtw[3]);

	/* post transform */
	
	return stop;
}
int instr_lnop(u32 opcode)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("lnop %08x\n", opcode);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_nop(u32 opcode)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("nop %08x\n", opcode);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_sync(u32 opcode)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sync %08x\n", opcode);
	/* optional trapping */
	
	/* body */
	#ifdef DEBUG_INSTR
	if ((opcode >> 20) & 1)
		vdbgprintf("  sync.c\n");
	else
		vdbgprintf("  sync\n");
#endif

	/* post transform */
	
	return stop;
}
int instr_dsync(u32 opcode)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("dsync %08x\n", opcode);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_mfspr(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mfspr $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		printf("########## WARNING #################\n");
	printf("    mfspr $%d, $%d not implemented!\n", rb, rt);
	printf("####################################\n");

	/* post transform */
	
	return stop;
}
int instr_mtspr(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mtspr $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		printf("########## WARNING #################\n");
	printf("    mtspr $%d, $%d not implemented!\n", rb, rt);
	printf("####################################\n");

	/* post transform */
	
	return stop;
}
int instr_rdch(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rdch $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	if (ctx->trap) return 1;
	/* body */
		channel_rdch(ra, rt);

	/* post transform */
	
	return stop;
}
int instr_wrch(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("wrch $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	if (ctx->trap) return 1;
	/* body */
		channel_wrch(ra, rt);

	/* post transform */
	
	return stop;
}
int instr_rchcnt(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rchcnt $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	if (ctx->trap) return 1;
	/* body */
		int i;
	for (i = 1; i < 4; ++i)
		rtw[i] = 0;

	rtw[0] = channel_rchcnt(ra);

	/* post transform */
	
	return stop;
}
int instr_bra(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("bra $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		ctx->pc = i16 - 4;

	/* post transform */
	
	return stop;
}
int instr_br(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("br $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		ctx->pc += i16 - 4;

	/* post transform */
	
	return stop;
}
int instr_brz(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("brz $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		if (rtw[0] == 0)
		ctx->pc += i16 - 4;

	/* post transform */
	
	return stop;
}
int instr_brnz(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);i16 <<= 2;
	/* show disassembly*/
	vdbgprintf("brnz $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		if (rtw[0] != 0)
		ctx->pc += i16 - 4;

	/* post transform */
	
	return stop;
}
int instr_bisl(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("bisl $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = 0;
	rtw[0] = ctx->pc + 4;
	ctx->pc = raw[0] - 4;

	/* post transform */
	
	return stop;
}
int instr_brsl(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	i16 = se16(i16);
	/* show disassembly*/
	vdbgprintf("brsl $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = 0;
	rtw[0] = ctx->pc + 4;
	ctx->pc += (i16 << 2) - 4;

	/* post transform */
	
	return stop;
}
int instr_bihnz(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("bihnz $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		if (rthp != 0)
		ctx->pc = raw[0] - 4;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_bihz(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("bihz $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		if (rthp == 0)
		ctx->pc = raw[0] - 4;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_brhnz(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);i16 = se16(i16);
	/* show disassembly*/
	vdbgprintf("brhnz $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		if (rthp != 0)
		ctx->pc += (i16 << 2) - 4;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_brhz(u32 rt, u32 i16)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i16; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);i16 = se16(i16);
	/* show disassembly*/
	vdbgprintf("brhz $r%d,%d\n", rt,i16);
	/* optional trapping */
	
	/* body */
		if (rthp == 0)
		ctx->pc += (i16 << 2) - 4;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_bi(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("bi $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		ctx->pc = raw[0] - 4;

	/* post transform */
	
	return stop;
}
int instr_biz(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("biz $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		if(rtw[0] == 0)
		ctx->pc = raw[0] - 4;

	/* post transform */
	
	return stop;
}
int instr_binz(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("binz $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		if(rtw[0] != 0)
		ctx->pc = raw[0] - 4;

	/* post transform */
	
	return stop;
}
int instr_hbr(u32 opcode)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)opcode; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("hbr %08x\n", opcode);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_hbra(u32 rt, u32 i18)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i18; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("hbra $r%d,0x%x\n", rt,i18);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_hbrr(u32 rt, u32 i18)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)i18; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("hbrr $r%d,0x%x\n", rt,i18);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_ah(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("ah $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = rah[i] + rbh[i];

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_ahi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("ahi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = rah[i] + i10;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_a(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("a $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	  rtw[i] = raw[i] + rbw[i];

	/* post transform */
	
	return stop;
}
int instr_ai(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("ai $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] + i10;

	/* post transform */
	
	return stop;
}
int instr_sfh(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("sfh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = rbh[i] - rah[i];

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_sfhi(u32 rt, u32 ra, u32 i10)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sfhi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_sf(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sf $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = rbw[i] - raw[i];

	/* post transform */
	
	return stop;
}
int instr_sfi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sfi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int imm = se10(i10);
	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = imm - raw[i];

	/* post transform */
	
	return stop;
}
int instr_addx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("addx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (rtw[i]&1) + raw[i] + rbw[i];

	/* post transform */
	
	return stop;
}
int instr_cg(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cg $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = ((raw[i] + rbw[i]) < raw[i]) ? 1 : 0;

	/* post transform */
	
	return stop;
}
int instr_cgx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cgx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	{
		u64 r = (u64)raw[i] + (u64)rbw[i] + (u64)(rtw[i] & 1);
		rtw[i] = (r >> 32) & 1;
	}

	/* post transform */
	
	return stop;
}
int instr_sfx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sfx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = rbw[i] - raw[i] - 1 + (rtw[i] & 1);

	/* post transform */
	
	return stop;
}
int instr_bg(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("bg $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (rbw[i] >= raw[i]) ? 1 : 0;

	/* post transform */
	
	return stop;
}
int instr_bgx(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("bgx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	{
		u64 r = (u64)(u32)(~raw[i]) + (u64)rbw[i] + (u64)(rtw[i] & 1);
		rtw[i] = (r >> 32) & 1;
	}

	/* post transform */
	
	return stop;
}
int instr_mpy(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpy $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_mpyu(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyu $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (raw[i] & 0xFFFF) * (rbw[i] & 0xFFFF);

	/* post transform */
	
	return stop;
}
int instr_mpyi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("mpyi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (s32)(s16)(raw[i] & 0xFFFF) * (s32)i10;

	/* post transform */
	
	return stop;
}
int instr_mpyui(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("mpyui $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		i10 &= 0xFFFF;
	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (raw[i] & 0xFFFF) * i10;

	/* post transform */
	
	return stop;
}
int instr_mpya(u32 rt, u32 ra, u32 rb, u32 rc)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb;(void)rc; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpya $r%d,$r%d,$r%d,$r%d\n", rt,ra,rb,rc);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_mpyh(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = ((raw[i] >> 16) * (rbw[i] & 0xFFFF)) << 16;

	/* post transform */
	
	return stop;
}
int instr_mpys(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpys $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = se16(((raw[i]&0xFFFF) * (rbw[i]&0xFFFF)) >> 16);

	/* post transform */
	
	return stop;
}
int instr_mpyhh(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyhh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (s32)(s16)(raw[i] >> 16) * (s32)(s16)(rbw[i] >> 16);

	/* post transform */
	
	return stop;
}
int instr_mpyhha(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyhha $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_mpyhhu(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyhhu $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (raw[i] >> 16) * (rbw[i] >> 16);

	/* post transform */
	
	return stop;
}
int instr_mpyhhau(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("mpyhhau $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_clz(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("clz $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	{
		int b;
		for (b = 0; b < 32; ++b)
			if (raw[i] & (1<<(31-b)))
				break;
		rtw[i] = b;
	}

	/* post transform */
	
	return stop;
}
int instr_cntb(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cntb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_fsmb(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("fsmb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_fsmh(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("fsmh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_fsm(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("fsm $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (rawp & (8>>i)) ? ~0 : 0;

	/* post transform */
	
	return stop;
}
int instr_gbb(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("gbb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = 0;
	for (i = 0; i < 16; ++i)
		rtb[2 + (i / 8)] |= (rab[i]&1) << ((~i)&7);

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_gbh(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("gbh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_gb(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("gb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		rtw[0] = ((raw[0] & 1) << 3) | ((raw[1] & 1) << 2) | ((raw[2] & 1) << 1) | (raw[3] & 1) ;
	rtw[1] = rtw[2] = rtw[3] = 0;

	/* post transform */
	
	return stop;
}
int instr_avgb(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("avgb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_absdb(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("absdb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_sumb(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("sumb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_xsbh(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("xsbh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; i += 2)
	{
		rtb[i] = rab[i + 1] & 0x80 ? 0xFF : 0;
		rtb[i + 1] = rab[i + 1];
	}

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_xshw(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("xshw $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; i += 2)
	{
		rth[i] = (rah[i + 1] & 0x8000) ? 0xFFFF : 0;
		rth[i + 1] = rah[i + 1];
	}

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_xswd(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("xswd $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		rtw[0] = (raw[1] & 0x80000000) ? 0xFFFFFFFF : 0;
	rtw[1] = raw[1];
	rtw[2] = (raw[3] & 0x80000000) ? 0xFFFFFFFF : 0;
	rtw[3] = raw[3];

	/* post transform */
	
	return stop;
}
int instr_and(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("and $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] & rbw[i];

	/* post transform */
	
	return stop;
}
int instr_andc(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("andc $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] &~ rbw[i];

	/* post transform */
	
	return stop;
}
int instr_andbi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("andbi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = rab[i] & i10;

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_andhi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("andhi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = rah[i] & i10;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_andi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("andi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] & i10;

	/* post transform */
	
	return stop;
}
int instr_or(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("or $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] | rbw[i];

	/* post transform */
	
	return stop;
}
int instr_orc(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("orc $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] |~ rbw[i];

	/* post transform */
	
	return stop;
}
int instr_orbi(u32 rt, u32 ra, u32 i10)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("orbi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_orhi(u32 rt, u32 ra, u32 i10)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("orhi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_ori(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("ori $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int imm = se10(i10);
	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] | imm;

	/* post transform */
	
	return stop;
}
int instr_orx(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("orx $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_xor(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("xor $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] ^ rbw[i];

	/* post transform */
	
	return stop;
}
int instr_xorbi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("xorbi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = rab[i] ^ (i10&0xFF);

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_xorhi(u32 rt, u32 ra, u32 i10)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("xorhi $r%d,$r%d,0x%x\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_xori(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("xori $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = raw[i] ^ i10;		

	/* post transform */
	
	return stop;
}
int instr_nand(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("nand $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_nor(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("nor $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = ~(raw[i] | rbw[i]);

	/* post transform */
	
	return stop;
}
int instr_eqv(u32 rt, u32 ra, u32 rb)
{
	int stop = 1;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("eqv $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
	
	/* post transform */
	
	return stop;
}
int instr_selb(u32 rt, u32 ra, u32 rb, u32 rc)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb;(void)rc; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("selb $r%d,$r%d,$r%d,$r%d\n", rt,ra,rb,rc);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (rcw[i] & rbw[i]) | ((~rcw[i]) & raw[i]);

	/* post transform */
	
	return stop;
}
int instr_shufb(u32 rt, u32 ra, u32 rb, u32 rc)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb;(void)rc; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);u8 rcb[16]; reg_to_byte(rcb, rc);
	/* show disassembly*/
	vdbgprintf("shufb $r%d,$r%d,$r%d,$r%d\n", rt,ra,rb,rc);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
	{
		if ((rcb[i] & 0xC0) == 0x80)
			rtb[i] = 0;
		else if ((rcb[i] & 0xE0) == 0xC0)
			rtb[i] = 0xFF;
		else if ((rcb[i] & 0xE0) == 0xE0)
			rtb[i] = 0x80;
		else
		{
			int b = rcb[i] & 0x1F;
			if (rcb[i] < 16)
				rtb[i] = rab[b];
			else
				rtb[i] = rbb[b-16];
		}
	}

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_shlqbyi(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("shlqbyi $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		i7 &= 0x1F;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = (i + i7) >= 16 ? 0 : rab[i + i7];

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_rotqbyi(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("rotqbyi $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		i7 &= 0x1F;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = rab[(i + i7) & 15];

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_rotqmbyi(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("rotqmbyi $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = (-i7) & 0x1f;

	int i;
	for (i = 0; i < 16; ++i)
	{
		if (i >= shift_count)
			rtb[i] = rab[i - shift_count];
		else
			rtb[i] = 0;
	}

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_rotqmbii(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u1 rtB[128]; reg_to_Bits(rtB, rt);u1 raB[128]; reg_to_Bits(raB, ra);
	/* show disassembly*/
	vdbgprintf("rotqmbii $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = (-i7) & 7;

	int i;
	for (i = 0; i < 128; ++i)
	{
		if (i >= shift_count)
			rtB[i] = raB[i - shift_count];
		else
			rtB[i] = 0;
	}

	/* post transform */
	Bits_to_reg(rt, rtB);
	return stop;
}
int instr_rotqbii(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u1 rtB[128]; reg_to_Bits(rtB, rt);u1 raB[128]; reg_to_Bits(raB, ra);
	/* show disassembly*/
	vdbgprintf("rotqbii $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = i7 & 7;

	int i;
	for (i = 0; i < 128; ++i)
	{
		rtB[i] = raB[(i + shift_count) & 127];
	}

	/* post transform */
	Bits_to_reg(rt, rtB);
	return stop;
}
int instr_shlqbi(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u1 rtB[128]; reg_to_Bits(rtB, rt);u1 raB[128]; reg_to_Bits(raB, ra);u1 rbB[128]; reg_to_Bits(rbB, rb);
	/* show disassembly*/
	vdbgprintf("shlqbi $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int shift_count = rbwp & 7;

	int i;
	for (i = 0; i < 128; ++i)
	{
		if (i + shift_count < 128)
			rtB[i] = raB[i + shift_count];
		else
			rtB[i] = 0;
	}

	/* post transform */
	Bits_to_reg(rt, rtB);
	return stop;
}
int instr_rotqmbi(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u1 rtB[128]; reg_to_Bits(rtB, rt);u1 raB[128]; reg_to_Bits(raB, ra);u1 rbB[128]; reg_to_Bits(rbB, rb);
	/* show disassembly*/
	vdbgprintf("rotqmbi $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int shift_count = (-rbwp) & 7;

	int i;
	for (i = 0; i < 128; ++i)
	{
		if (i >= shift_count)
			rtB[i] = raB[i - shift_count];
		else
			rtB[i] = 0;
	}

	/* post transform */
	Bits_to_reg(rt, rtB);
	return stop;
}
int instr_shlqbii(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u1 rtB[128]; reg_to_Bits(rtB, rt);u1 raB[128]; reg_to_Bits(raB, ra);
	/* show disassembly*/
	vdbgprintf("shlqbii $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = i7 & 7;

	int i;
	for (i = 0; i < 128; ++i)
	{
		if (i + shift_count < 128)
			rtB[i] = raB[i + shift_count];
		else
			rtB[i] = 0;
	}

	/* post transform */
	Bits_to_reg(rt, rtB);
	return stop;
}
int instr_rotqby(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("rotqby $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int shift = rbw[0] & 0xF;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = rab[(i + shift) & 15];

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_shlqby(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("shlqby $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int shift = rbw[0] & 0x1F;
	
	int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = (i + shift) < 16 ? rab[i + shift] : 0;

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_rotqmby(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("rotqmby $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		u32 s = (-rbw[0]) & 0x1F;

	u32 i;
	for (i = 0; i < 16; ++i)
		if (i >= s)
			rtb[i] = rab[i - s];
		else
			rtb[i] = 0;

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_rotmi(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rotmi $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = (-i7) & 63;
	int i;
	for (i = 0; i < 4; ++i)
		if (shift_count < 32)
			rtw[i] = raw[i] >> shift_count;
		else
			rtw[i] = 0;

	/* post transform */
	
	return stop;
}
int instr_rothmi(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("rothmi $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = (-i7) & 31;
	int i;
	for (i = 0; i < 8; ++i)
		if (shift_count < 16)
			rth[i] = rah[i] >> shift_count;
		else
			rth[i] = 0;

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_rotm(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rotm $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	{
		int shift_count = (-rbw[i]) & 63;
		if (shift_count < 32)
			rtw[i] = raw[i] >> shift_count;
		else
			rtw[i] = 0;
	}

	/* post transform */
	
	return stop;
}
int instr_rotmai(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rotmai $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = (-i7) & 63;
	int i;
	for (i = 0; i < 4; ++i)
		if (shift_count < 32)
			rtw[i] = ((s32)raw[i]) >> shift_count;
		else
			rtw[i] = ((s32)raw[i]) >> 31;

	/* post transform */
	
	return stop;
}
int instr_rotma(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("rotma $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i,shift_count;
	for (i = 0; i < 4; ++i){
		shift_count = (-rbw[i]) & 63;
		if (shift_count < 32)
			rtw[i] = ((s32)raw[i]) >> shift_count;
		else
			rtw[i] = ((s32)raw[i]) >> 31;
	}

	/* post transform */
	
	return stop;
}
int instr_shli(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("shli $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int i;
	int shift_count = i7 & 0x3f;
	for (i = 0; i < 4; ++i)
	{
		if (shift_count > 31)
			rtw[i] = 0;
		else
			rtw[i] = raw[i] << shift_count;
	}

	/* post transform */
	
	return stop;
}
int instr_shl(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("shl $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
	{
		int shift_count = rbw[i] & 0x3f;
		if (shift_count > 31)
			rtw[i] = 0;
		else
			rtw[i] = raw[i] << shift_count;
	}

	/* post transform */
	
	return stop;
}
int instr_roti(u32 rt, u32 ra, u32 i7)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i7; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("roti $r%d,$r%d,0x%x\n", rt,ra,i7);
	/* optional trapping */
	
	/* body */
		int shift_count = i7 & 0x1F;
	int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = (raw[i] << shift_count) | (raw[i] >> (32 - shift_count));

	/* post transform */
	
	return stop;
}
int instr_ceqi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("ceqi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;

	for (i = 0; i < 4; ++i)
		rtw[i] = -(raw[i] == i10);

	/* post transform */
	
	return stop;
}
int instr_ceqhi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("ceqhi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;

	for (i = 0; i < 8; ++i)
		rth[i] = -(rah[i] == i10);

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_ceqh(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("ceqh $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;

	for (i = 0; i < 8; ++i)
		rth[i] = -(rah[i] == rbh[i]);

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_ceq(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("ceq $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = -(raw[i] == rbw[i]);

	/* post transform */
	
	return stop;
}
int instr_clgt(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("clgt $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = -(raw[i] > rbw[i]);

	/* post transform */
	
	return stop;
}
int instr_cgt(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	
	/* show disassembly*/
	vdbgprintf("cgt $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = -(((s32)raw[i]) > ((s32)rbw[i]));

	/* post transform */
	
	return stop;
}
int instr_ceqbi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("ceqbi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = -(rab[i] == (i10 & 0xFF));

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_ceqb(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("ceqb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = -(rab[i] == rbb[i]);

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_clgtb(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);u8 rbb[16]; reg_to_byte(rbb, rb);
	/* show disassembly*/
	vdbgprintf("clgtb $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = -(rab[i] > rbb[i]);

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_cgthi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("cgthi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = -(((s16)rah[i]) > ((s16)i10));

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_clgti(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("clgti $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = -(raw[i] > i10);

	/* post transform */
	
	return stop;
}
int instr_clgthi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);
	/* show disassembly*/
	vdbgprintf("clgthi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = -(rah[i] > i10);

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_clgth(u32 rt, u32 ra, u32 rb)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)rb; 
	/* pre transform */
	u16 rth[8]; reg_to_half(rth, rt);u16 rah[8]; reg_to_half(rah, ra);u16 rbh[8]; reg_to_half(rbh, rb);
	/* show disassembly*/
	vdbgprintf("clgth $r%d,$r%d,$r%d\n", rt,ra,rb);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 8; ++i)
		rth[i] = -(rah[i] > rbh[i]);

	/* post transform */
	half_to_reg(rt, rth);
	return stop;
}
int instr_clgtbi(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);u8 rtb[16]; reg_to_byte(rtb, rt);u8 rab[16]; reg_to_byte(rab, ra);
	/* show disassembly*/
	vdbgprintf("clgtbi $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 16; ++i)
		rtb[i] = -(rab[i] > (i10&0xFF));

	/* post transform */
	byte_to_reg(rt, rtb);
	return stop;
}
int instr_cgti(u32 rt, u32 ra, u32 i10)
{
	int stop = 0;
	/* ignore unused arguments */
	(void)rt;(void)ra;(void)i10; 
	/* pre transform */
	i10 = se10(i10);
	/* show disassembly*/
	vdbgprintf("cgti $r%d,$r%d,%d\n", rt,ra,i10);
	/* optional trapping */
	
	/* body */
		int i;
	for (i = 0; i < 4; ++i)
		rtw[i] = -(((s32)raw[i]) > ((s32)i10));

	/* post transform */
	
	return stop;
}

