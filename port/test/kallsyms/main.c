/* kallsyms differential: the pristine table walkers (ARM_REF: ref.c extracted from the pristine file) against kallsyms_rs.rs plus the glue wrappers (ARM_RS). The tables are generated
 * here, in the format scripts/kallsyms writes: compressed names ([len] or [0x80|len&0x7f][len>>7] then token bytes; the first character of an expansion is the symbol type), a token table
 * with single-character and multi-character tokens, markers every 256 symbols, sorted address offsets with aliases, 3-byte sequence numbers sorted by name with duplicate names. Random
 * table sizes (1..900 symbols, big symbols over 127 compressed bytes), then expansion with every buffer size, type lookup, offset of every position, lookups of present, absent, prefix and
 * duplicate names, and address searches below, inside and past the table with the section-end fallbacks.   usage: t SHARD (env KS_N, KS_PROVE) */
#include "refshim.h"
const int *kallsyms_offsets; const u8 *kallsyms_names; unsigned int kallsyms_num_syms; unsigned long kallsyms_relative_base; const char *kallsyms_token_table; const u16 *kallsyms_token_index;
const unsigned int *kallsyms_markers; const u8 *kallsyms_seqs_of_names; int ks_all_g; unsigned long init_lo_g, init_hi_g;
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
#define MAXS 1000
static u8 *names, *seqs; static unsigned *markers; static int *offsets; static char tokbuf[4096]; static u16 tokidx[256]; static char *sname[MAXS]; static unsigned nsyms; static unsigned seqord[MAXS];
static int cmpname(const void *a, const void *b) { unsigned x = *(const unsigned *)a, y = *(const unsigned *)b; int c = strcmp(sname[x], sname[y]); return c ? c : (x > y) - (x < y); }
static void gen_tables(void)
{
	static const char al[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.$"; size_t tp = 0, np = 0; unsigned i, k; static u8 cmp[40000];
	for (k = 0; k < 256; k++) {   /* tokens: bytes 0..127 one character, 128..255 two to four characters (a token's first byte is never NUL) */
		unsigned l = k < 128 ? 1 : 2 + rnd(3); tokidx[k] = tp; for (i = 0; i < l; i++) tokbuf[tp++] = rnd(25) ? al[rnd(sizeof al - 1)] : (char)(0x80 + rnd(120)); tokbuf[tp++] = 0;
	}
	nsyms = 1 + (rnd(4) ? rnd(300) : rnd(MAXS)); free(names); names = malloc(nsyms * 400 + 16); free(markers); markers = malloc(sizeof(unsigned) * (nsyms / 256 + 2));
	for (i = 0; i < nsyms; i++) {
		unsigned ntok = rnd(8) == 0 ? 120 + rnd(200) : 1 + rnd(14), cl = 0, t; char buf[2048]; size_t bl = 0; u8 *c = cmp;
		if (i % 256 == 0) markers[i / 256] = np;
		for (t = 0; t < ntok; t++) { u8 b = rnd(2) ? (u8)(128 + rnd(128)) : (u8)rnd(128); c[cl++] = b; { const char *s = tokbuf + tokidx[b]; while (*s) buf[bl++] = *s++; } }
		if (bl < 2 && 0) bl = 2;
		buf[bl] = 0;
		/* the expansion is the type character followed by the name; the symbol name is the rest */
		{ size_t st = 0; char *nm = malloc(bl + 1); memcpy(nm, buf + 1, bl > 0 ? bl - 1 : 0); nm[bl > 0 ? bl - 1 : 0] = 0; sname[i] = nm; (void)st; }
		if (cl < 128) names[np++] = cl; else { names[np++] = 0x80 | (cl & 0x7f); names[np++] = cl >> 7; }
		memcpy(names + np, c, cl); np += cl;
	}
	free(seqs); seqs = malloc(3 * nsyms + 3); for (i = 0; i < nsyms; i++) seqord[i] = i; qsort(seqord, nsyms, sizeof(unsigned), cmpname);
	for (i = 0; i < nsyms; i++) { seqs[3 * i] = seqord[i] >> 16; seqs[3 * i + 1] = seqord[i] >> 8; seqs[3 * i + 2] = seqord[i]; }
	free(offsets); offsets = malloc(sizeof(int) * (nsyms + 1)); { unsigned a = rnd(100); int dense = rnd(3) == 0; for (i = 0; i < nsyms; i++) { offsets[i] = (int)a; a += dense ? rnd(3) : rnd(rnd(4) ? 5000 : 2000000000u); if (a > 0xffffff00u) a = 0xffffff00u; } }
	kallsyms_names = names; kallsyms_markers = markers; kallsyms_token_table = tokbuf; kallsyms_token_index = tokidx; kallsyms_offsets = offsets; kallsyms_seqs_of_names = seqs; kallsyms_num_syms = nsyms;
	kallsyms_relative_base = rnd(3) ? 0xffffffff81000000UL : (rnd(2) ? 0UL : (unsigned long)rnd64() << 8); ks_all_g = rnd(2); init_lo_g = kallsyms_relative_base + rnd(2000); init_hi_g = init_lo_g + rnd(3000);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("KS_N") ? atol(getenv("KS_N")) : 120; int prove = getenv("KS_PROVE") != NULL; long i; static int pc;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (i = 0; i < n; i++) {
		unsigned j, off; gen_tables(); printf("T%ld nsyms=%u base=%lx all=%d\n", i, nsyms, kallsyms_relative_base, ks_all_g);
		{   /* expansion of every symbol with random buffer sizes, the type, the offset of every position */
			unsigned o = 0; char buf[600]; static const size_t sizes[] = { 0, 1, 2, 3, 5, 17, 100, 511, 512, 600 };
			for (j = 0; j < nsyms; j++) {
				size_t ml = sizes[rnd(10)]; unsigned o2; memset(buf, 0x7e, sizeof buf);
				o2 = kallsyms_expand_symbol(o, buf, ml > sizeof buf ? sizeof buf : ml); if (prove && pc++ == 3) o2++;
				printf(" X%u o=%u ml=%zu -> %u [%.*s] t=%d off=%u\n", j, o, ml, o2, (int)(ml > 0 && ml <= sizeof buf ? ml : 0), buf, kallsyms_get_symbol_type(o), get_symbol_offset(j));
				o = o2; (void)ml;
			}
		}
		for (j = 0; j < 40; j++) {   /* names: present (a random symbol, as expanded), absent, prefixes, empty-ish */
			char nm[600]; unsigned pick = rnd(nsyms), st, en; int r, ret; unsigned a; (void)a;
			strcpy(nm, sname[pick]); if (rnd(4) == 0 && strlen(nm) > 1) nm[strlen(nm) - 1] = 0; if (rnd(5) == 0) strcat(nm, "x"); if (rnd(8) == 0) strcpy(nm, "");
			st = en = 0xdead; ret = kallsyms_lookup_names(nm, &st, rnd(3) ? &en : NULL); r = ret; off = 0;
			printf(" L[%s] -> %d %u %u addr=%lu\n", nm, r, st, en, r == 0 ? kallsyms_sym_address(get_symbol_seq(st)) : 0UL);
		}
		for (j = 0; j < 60; j++) {   /* addresses */
			unsigned long addr, size = 0x77, offs = 0x66, pos; unsigned idx = rnd(nsyms);
			addr = kallsyms_relative_base + (unsigned)offsets[idx] + (rnd(3) ? rnd(3) : rnd(100000)) - (rnd(4) == 0 ? rnd(3) : 0); if (rnd(8) == 0) addr = kallsyms_relative_base - rnd(100); if (rnd(8) == 0) addr = kallsyms_relative_base + 0x100000000UL + rnd(10);
			if (rnd(6) == 0) addr = init_lo_g + rnd(init_hi_g - init_lo_g + 1);
			pos = get_symbol_pos(addr, rnd(4) ? &size : NULL, rnd(4) ? &offs : NULL);
			printf(" A%lx -> %lu size=%lu off=%lu\n", addr, pos, size, offs);
		}
	}
	return 0;
}
