// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "channel.h"
#include "helper.h"

static u32 MFC_LSA, MFC_EAH, MFC_EAL, MFC_Size, MFC_TagID, MFC_TagMask, MFC_TagStat;

#define MFC_GET_CMD 0x40
#define MFC_SNDSIG_CMD 0xA0



/* ===== harness: EA (main memory) model for full boot-flow tracing =====
 * ANERG_EA=<file>   backing image for effective-address space
 * Logs every DMA with a content checksum so re-fetches are visible.
 */
static unsigned char *ea_mem = NULL;
static size_t ea_size = 0;
static int ea_ready = 0;
static long dma_seq = 0;
static u32  g_ch64_last = 0;   /* last value written to the appldr request channel */

static void ea_setup(void)
{
	const char *f = getenv("ANERG_EA");
	ea_ready = 1;
	ea_size = 64u * 1024 * 1024;
	ea_mem = (unsigned char *)calloc(1, ea_size);
	if (f && ea_mem) {
		FILE *fp = fopen(f, "rb");
		if (fp) { if (fread(ea_mem, 1, ea_size, fp) == 0) {} fclose(fp); }
		taint_ea_init((u32)ea_size);
	}
}

static u32 sum32(const unsigned char *p, u32 n)
{
	u32 h = 2166136261u, i;
	for (i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
	return h;
}

void handle_mfc_command(u32 cmd)
{
	u32 lsa, sz, chk = 0;
	unsigned long long ea;
	int isget, isput;

	if (!ea_ready) ea_setup();
	lsa = MFC_LSA & 0x3ffff;
	sz  = MFC_Size;
	ea  = ((unsigned long long)MFC_EAH << 32) | MFC_EAL;
	/* ANERG_EATAG=<hex mask>: clear these bits of the EA before touching the
	 * backing store.  lv1 hands the loaders TAGGED REAL ADDRESSES (top nibble
	 * 1, plus attribute bits -- notes/149, notes/150), which are far outside
	 * the emulator's flat EA image, so every such transfer silently reads
	 * zeros and the loader dies on the resulting garbage.  This strips the tag
	 * so the transfer lands in the image.  It changes only where the harness
	 * looks, never what the loader computes. */
	{ static int et = -1; static unsigned long long etm;
	  if (et < 0) { const char *e = getenv("ANERG_EATAG");
	                et = (e != NULL); etm = et ? strtoull(e, NULL, 16) : 0ull; }
	  if (et) ea &= ~etm; }
	isget = ((cmd & 0xf0) == 0x40);
	isput = ((cmd & 0xf0) == 0x20);

	if (ea_mem && sz && sz <= 0x4000 && ea + sz <= (unsigned long long)ea_size
	    && (unsigned long long)lsa + sz <= 0x40000ull) {
		if (isget) {
			memcpy(ctx->ls + lsa, ea_mem + (size_t)ea, sz);
			rbw_mark_range(lsa, sz);
			taint_dma_in(lsa, (u32)ea, sz);
			chk = sum32(ctx->ls + lsa, sz);
		} else if (isput) {
			memcpy(ea_mem + (size_t)ea, ctx->ls + lsa, sz);
			chk = sum32(ea_mem + (size_t)ea, sz);
			fprintf(stderr, "[PUTSRC] LS[%05x..%05x] first16=%02x%02x%02x%02x%02x%02x%02x%02x"
			        "%02x%02x%02x%02x%02x%02x%02x%02x\n", lsa, lsa+sz,
			        ctx->ls[lsa+0],ctx->ls[lsa+1],ctx->ls[lsa+2],ctx->ls[lsa+3],
			        ctx->ls[lsa+4],ctx->ls[lsa+5],ctx->ls[lsa+6],ctx->ls[lsa+7],
			        ctx->ls[lsa+8],ctx->ls[lsa+9],ctx->ls[lsa+10],ctx->ls[lsa+11],
			        ctx->ls[lsa+12],ctx->ls[lsa+13],ctx->ls[lsa+14],ctx->ls[lsa+15]);
		}
	}
	/* harness: ANERG_DBGCHAR=1 -- sc_iso (and friends) emit a debug character
	 * stream as a run of one-byte MFC PUTs to a fixed host address. psdevwiki
	 * documents that printing, and it is the module narrating its own internal
	 * state and error codes. Capture it instead of dropping it. */
	{ static int dc = -1;
	  if (dc < 0) { const char *e = getenv("ANERG_DBGCHAR"); dc = (e && *e == '1'); }
	  if (dc && isput && sz == 1) {
		unsigned char ch = ctx->ls[lsa & 0x3ffff];
		if ((ch >= 32 && ch < 127) || ch == '\n') fputc(ch, stderr);
		fflush(stderr);
		return;                      /* do not log it as a DMA line */
	  } }

	printf("[DMA%03ld] %s LSA=%05x EA=%08x:%08x SIZE=%06x TAG=%x CMD=%02x SUM=%08x\n",
	       dma_seq, isget ? "GET" : (isput ? "PUT" : "???"),
	       lsa, MFC_EAH, MFC_EAL, sz, MFC_TagID, cmd, chk);
	/* harness: ANERG_POISON="<after_dma_n>:<ea_off>" -- flip a byte in EA AFTER
	 * transfer n completes, to test time-of-check/time-of-use. */
	{
		const char *ps = getenv("ANERG_POISON");
		if (ps && ea_mem) {
			long n = strtol(ps, NULL, 0);
			const char *c = strchr(ps, ':');
			if (c && n == dma_seq) {
				size_t off = (size_t)strtoul(c + 1, NULL, 0);
				if (off < ea_size) {
					ea_mem[off] ^= 0x01;
					printf("[POISON] flipped bit0 of EA %#zx after DMA%03ld\n", off, n);
				}
			}
		}
	}
	dma_seq++;
	fflush(stdout);
}

void handle_mfc_tag_update(u32 tag)
{
	switch (tag)
	{
	case 0:
	default:
		/* harness: DMA is synchronous here, so every tag update completes */
		MFC_TagStat = MFC_TagMask;
		break;
	}
}

/* --- harness: SPU inbound/outbound mailbox emulation (ch29 / ch30) --- */
u32 g_inbox[64]; int g_inbox_n = 0; int g_inbox_rd = 0;
int g_outbox_n = 0;

void channel_wrch(int ch, int reg)
{
	if (!getenv("ANERG_MBOX")) printf("CHANNEL: wrch ch%d r%d\n", ch, reg);
	u32 r = ctx->reg[reg][0];
	
	switch (ch)
	{
	case 16:
		printf("MFC_LSA %08x\n", r);
		MFC_LSA = r;
		break;
	case 17:
		printf("MFC_EAH %08x\n", r);
		MFC_EAH = r;
		break;
	case 18:
		printf("MFC_EAL %08x\n", r);
		MFC_EAL = r;
		break;
	case 19:
		printf("MFC_Size %08x\n", r);
		MFC_Size = r;
		break;
	case 20:
		printf("MFC_TagID %08x\n", r);
		MFC_TagID =r ;
		break;
	case 21:
		printf("MFC_Cmd %08x\n", r);
		handle_mfc_command(r);
		break;
	case 22:
		printf("MFC_WrTagMask %08x\n", r);
		MFC_TagMask = r;
		break;
	case 23:
		printf("MFC_WrTagUpdate %08x\n", r);
		handle_mfc_tag_update(r);
		break;
	case 30:
		printf("[mbox-out] %08x\n", ctx->reg[reg][0]);
		g_outbox_n++;
		break;

	case 26:
		printf("MFC_WrListStallAck %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	case 28: {   /* SPU_WrOutMbox -- harness: capture to ANERG_MBOX file */
		static FILE *mb = NULL; static int tried = 0;
		if (!tried) { const char *f = getenv("ANERG_MBOX");
		              if (f) mb = fopen(f, "wb"); tried = 1; }
		if (mb) { unsigned char b[4] = { r>>24, r>>16, r>>8, r };
		          fwrite(b, 1, 4, mb); }
		break;
	}
	case 64:   /* appldr request/command channel (non-CBEA, Sony-specific).
	              Sequence at appldr 0x27418: ila $2,0x10000 ; wrch $ch64,$2 ;
	              then N reads from ch73.  Model it as a request register. */
		g_ch64_last = r;
		printf("CH64_REQ %08x\n", r);
		break;
	default:
		printf("UNKNOWN CHANNEL\n");
	}
}

void channel_rdch(int ch, int reg)
{
	taint_chan(ch, reg);
	printf("CHANNEL: rdch ch%d r%d\n", ch, reg);
	u32 r;
	
	r = 0;
	switch (ch)
	{
	case 29:                                  /* SPU_RdInMbox */
		if (g_inbox_rd < g_inbox_n) {
			r = g_inbox[g_inbox_rd++];
			printf("[mbox-in] -> %08x\n", r);
		} else r = 0;
		break;
	case 24:
		r = MFC_TagStat;
		printf("MFC_RdTagStat %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	case 73: {  /* appldr/isoldr data-in channel, paired with ch64.
	               ch73 is REQUEST/RESPONSE, not a tape: isoldr asks the same
	               request repeatedly and expects the same answer each time.
	               Serving a flat file sequentially answers the first ask and
	               returns zeros forever after, which makes isoldr spin
	               (notes/139).  So each distinct ch64 request gets its OWN
	               cursor, and ANERG_CH73MAP lets a request be answered
	               explicitly:
	                   ANERG_CH73MAP="00010000:0004009300000000,00060000:...."
	               ANERG_CH73 remains the fallback tape for unmapped requests. */
		enum { CH73_MAX = 16 };
		static int init = 0;
		static u32 mreq[CH73_MAX]; static unsigned char *mbuf[CH73_MAX];
		static long mlen[CH73_MAX], mpos[CH73_MAX]; static int mn = 0;
		static unsigned char *fbuf = NULL; static long flen = 0, fpos = 0;
		if (!init) {
			init = 1;
			const char *f = getenv("ANERG_CH73");
			if (f) { FILE *fp = fopen(f, "rb");
			         if (fp) { fseek(fp,0,SEEK_END); flen=ftell(fp); fseek(fp,0,SEEK_SET);
			                   fbuf=(unsigned char*)malloc(flen?flen:1);
			                   if (fbuf && fread(fbuf,1,flen,fp)!=(size_t)flen) flen=0;
			                   fclose(fp); } }
			const char *m = getenv("ANERG_CH73MAP");
			if (m) {
				char tmp[4096]; strncpy(tmp,m,sizeof tmp-1); tmp[sizeof tmp-1]=0;
				char *sv=NULL, *tok=strtok_r(tmp,",",&sv);
				while (tok && mn < CH73_MAX) {
					char hex[2048]; u32 rq=0;
					if (sscanf(tok,"%x:%2047s",&rq,hex)==2) {
						long n=strlen(hex)/2;
						unsigned char *b=(unsigned char*)malloc(n?n:1);
						for (long i=0;i<n;i++){ unsigned v; sscanf(hex+2*i,"%2x",&v); b[i]=(unsigned char)v; }
						mreq[mn]=rq; mbuf[mn]=b; mlen[mn]=n; mpos[mn]=0; mn++;
					}
					tok=strtok_r(NULL,",",&sv);
				}
			}
		}
		int hit = -1;
		for (int i=0;i<mn;i++) if (mreq[i]==g_ch64_last) { hit=i; break; }
		if (hit >= 0) {
			if (mpos[hit] + 4 > mlen[hit]) mpos[hit] = 0;      /* repeat the answer */
			r = (mbuf[hit][mpos[hit]]<<24)|(mbuf[hit][mpos[hit]+1]<<16)
			  | (mbuf[hit][mpos[hit]+2]<<8)|mbuf[hit][mpos[hit]+3];
			mpos[hit] += 4;
		} else if (fbuf && fpos + 4 <= flen) {
			r = (fbuf[fpos]<<24)|(fbuf[fpos+1]<<16)|(fbuf[fpos+2]<<8)|fbuf[fpos+3];
			fpos += 4;
		} else r = 0;
		printf("CH73_DATA -> %08x (req %08x)%s\n", r, g_ch64_last,
		       hit>=0 ? " [mapped]" : "");
		break;
	}
	}
	ctx->reg[reg][0] = r;
	ctx->reg[reg][1] = 0;
	ctx->reg[reg][2] = 0;
	ctx->reg[reg][3] = 0;
}

int channel_rchcnt(int ch)
{
	u32 r;
	r = 0;
	switch (ch)
	{
	case 29:                                  /* pending inbound words */
		r = (g_inbox_rd < g_inbox_n) ? (u32)(g_inbox_n - g_inbox_rd) : 0;
		break;
	case 28:                                  /* SPU_WrOutMbox space free */
		r = 1;
		break;
	case 30:                                  /* outbound space free */
		r = 1;
		break;
	case 23:
		r = 1;
		break;
	case 24:
		r = 1;
		printf("MFC_RdTagStat %08x\n", r);
		break;
	case 27:
		printf("MFC_RdAtomicStat %08x\n", r);
		break;
	case 64:                                  /* request channel: always accepts */
	case 73:                                  /* data channel: always has a word */
		r = 1;
		break;
	default:
		printf("unknown channel %d\n", ch);
	}
	return r;
}
