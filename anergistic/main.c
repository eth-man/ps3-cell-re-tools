// Copyright 2010 fail0verflow <master@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2
// http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "types.h"
#include "main.h"
#include "config.h"
#include "elf.h"
#include "emulate.h"
#include "gdb.h"

struct ctx_t _ctx;
struct ctx_t *ctx;

static int gdb_port = -1;
static const char *elf_path = NULL;

void dump_regs(void)
{
	u32 i;

	printf("\nRegister dump:\n");
	printf(" pc:\t%08x\n", ctx->pc);
	for (i = 0; i < 128; i++)
		printf("%.3d:\t%08x %08x %08x %08x\n",
				i,
				ctx->reg[i][0],
				ctx->reg[i][1],
				ctx->reg[i][2],
				ctx->reg[i][3]
				);
}

void dump_ls(void)
{
	FILE *fp;

	printf("dumping local store to " DUMP_LS_NAME "\n");
	fp = fopen(DUMP_LS_NAME, "wb");
	fwrite(ctx->ls, LS_SIZE, 1, fp);
	fclose(fp);
}

void fail(const char *a, ...)
{
	char msg[1024];
	va_list va;

	va_start(va, a);
	vsnprintf(msg, sizeof msg, a, va);
	perror(msg);

#ifdef FAIL_DUMP_REGS
	dump_regs();
#endif

#ifdef FAIL_DUMP_LS
	dump_ls();
#endif

	gdb_deinit();
	exit(1);
}

/* --- harness additions: start PC, LS blob preload, register presets --- */
static long  start_pc  = -1;
static char *ls_blobs[16]; static int n_ls_blobs = 0;
static char *reg_sets[64]; static int n_reg_sets = 0;
static long  max_instrs = 0;
extern u32 g_inbox[64]; extern int g_inbox_n;

static void usage(void)
{
	printf("usage: anergistic [-g port] [-p startpc] [-L file@lsaddr] [-r N=hexword] [-m maxinstr] file.elf\n");
	exit(1);
}

static void parse_args(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, "g:p:L:r:m:i:")) != -1) {
		switch(c) {
			case 'g':
				gdb_port = strtol(optarg, NULL, 10);
				break;
			case 'p':
				start_pc = strtol(optarg, NULL, 0);
				break;
			case 'L':
				if (n_ls_blobs < 16) ls_blobs[n_ls_blobs++] = optarg;
				break;
			case 'r':
				if (n_reg_sets < 64) reg_sets[n_reg_sets++] = optarg;
				break;
			case 'm':
				max_instrs = strtol(optarg, NULL, 0);
				break;
			case 'i':
				if (g_inbox_n < 64)
					g_inbox[g_inbox_n++] = (u32)strtoul(optarg, NULL, 16);
				break;
			default:
				printf("Unknown argument: %c\n", c);
				usage();
		}
	}

	if (optind != argc - 1)
		usage();

	elf_path = argv[optind];
}

int main(int argc, char *argv[])
{
	u32 done;
	memset(&_ctx, 0x00, sizeof _ctx);
	ctx = &_ctx;
	parse_args(argc, argv);

#if 0
	u64 local_ptr;
	
	local_ptr = 0xdead0000dead0000ULL;
	
	ctx->reg[3][0] = (u32)(local_ptr >> 32);
	ctx->reg[3][1] = (u32)local_ptr;

	ctx->reg[4][0] = 0xdead0000;
	ctx->reg[4][1] = 0xdead0000;
#endif

	ctx->ls = malloc(LS_SIZE);
	if (ctx->ls == NULL)
		fail("Unable to allocate local storage.");
	memset(ctx->ls, 0, LS_SIZE);

#if 1
	wbe64(ctx->ls + 0x3f000, 0x100000000ULL);
	wbe32(ctx->ls + 0x3f008, 0x10000);
	wbe32(ctx->ls + 0x3e000, 0xff);
#endif

	if (gdb_port < 0) {
		ctx->paused = 0;
	} else {
		gdb_init(gdb_port);
		ctx->paused = 1;
		gdb_signal(SIGABRT);
	}

	elf_load(elf_path);

	/* --- harness: preload LS blobs (file@lsaddr) --- */
	for (int i = 0; i < n_ls_blobs; i++) {
		char *at = strrchr(ls_blobs[i], '@');
		if (!at) fail("-L needs file@lsaddr");
		*at = 0;
		u32 dst = (u32)strtoul(at + 1, NULL, 0);
		FILE *f = fopen(ls_blobs[i], "rb");
		if (!f) fail("cannot open -L file");
		fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
		if (dst + n > LS_SIZE) n = LS_SIZE - dst;
		if (fread(ctx->ls + dst, 1, n, f) != (size_t)n) { /* short read ok */ }
		fclose(f);
		fprintf(stderr, "[harness] loaded %ld bytes at LS 0x%05x\n", n, dst);
	}

	/* --- harness: register presets  N=hexword (replicated to all 4 slots) --- */
	for (int i = 0; i < n_reg_sets; i++) {
		char *eq = strchr(reg_sets[i], '=');
		if (!eq) fail("-r needs N=hexword");
		*eq = 0;
		int rn = atoi(reg_sets[i]);
		/* N=hexword          -> replicate to all four slots (original behaviour)
		 * N=w0:w1:w2:w3      -> set each 32-bit slot independently.  The isolated
		 *   module ABI passes 64-bit arguments in slots 0,1, so a replicated
		 *   value produces a nonsense high word (e.g. an EA above the backing
		 *   store) and the DMA is silently skipped. */
		if (rn >= 0 && rn < 128) {
			if (strchr(eq + 1, ':')) {
				char *sp2 = eq + 1;
				for (int w = 0; w < 4; w++) {
					char *nx = strchr(sp2, ':');
					if (nx) *nx = 0;
					ctx->reg[rn][w] = *sp2 ? (u32)strtoul(sp2, NULL, 16) : 0;
					if (!nx) { for (int k = w + 1; k < 4; k++) ctx->reg[rn][k] = 0; break; }
					sp2 = nx + 1;
				}
			} else {
				u32 v = (u32)strtoul(eq + 1, NULL, 16);
				ctx->reg[rn][0] = ctx->reg[rn][1] = ctx->reg[rn][2] = ctx->reg[rn][3] = v;
			}
			fprintf(stderr, "[harness] r%d = %08x %08x %08x %08x\n", rn,
				ctx->reg[rn][0], ctx->reg[rn][1], ctx->reg[rn][2], ctx->reg[rn][3]);
		}
	}

	/* --- harness: override entry --- */
	if (start_pc >= 0) {
		ctx->pc = (u32)start_pc;
		fprintf(stderr, "[harness] start pc = 0x%05x\n", ctx->pc);
	}

	done = 0;

	while(done == 0) {

		if (ctx->paused == 0)
			done = emulate();

		// data watchpoints
		if (done == 2) {
			ctx->paused = 0;
			gdb_signal(SIGTRAP);
			done = 0;
		}
		
		if (done != 0) {
			printf("emulated() returned, sending SIGSEGV to gdb stub\n");
			ctx->paused = 1;
			done = gdb_signal(SIGSEGV);
		}

		if (done != 0) {
#ifdef STOP_DUMP_REGS
			dump_regs();
#endif
#ifdef STOP_DUMP_LS
			dump_ls();
#endif
		}

		if (ctx->paused == 1)
			gdb_handle_events();
	}
	printf("emulate() returned. we're done!\n");
	dump_ls();
	free(ctx->ls);
	gdb_deinit();
	return 0;
}
