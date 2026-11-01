/* SPDX-License-Identifier: GPL-2.0 */
/* Differential for arch/x86/lib/insn.c + inat.c: the pristine C (tools/ sync copy, built with the c_ prefix)
 * vs insn_rs.rs, on the same bytes, through the same struct insn. Both return value AND the whole struct are compared.
 * Inputs sit at the END of a page followed by an unmapped guard page, so any over-read by either arm faults.
 *  inat   : every lookup over every attribute value reachable from the tables x all opcodes/modrm/prefix ids
 *  decode : all 1-, 2-, 3-byte sequences (both modes, several buffer lengths) + biased random 15-byte sequences
 *  stages : random orderings of insn_get_* / insn_rip_relative on the same insn
 * usage: main SHARD NSHARDS ; X86INSN_PROVE_CAN_FAIL=1 breaks the Rust arm. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <asm/insn.h>

#define CP(n) c_##n
void c_insn_init(struct insn *, const void *, int, int);
int c_insn_get_prefixes(struct insn *), c_insn_get_opcode(struct insn *), c_insn_get_modrm(struct insn *),
    c_insn_get_sib(struct insn *), c_insn_get_displacement(struct insn *), c_insn_get_immediate(struct insn *),
    c_insn_get_length(struct insn *), c_insn_rip_relative(struct insn *);
int c_insn_decode(struct insn *, const void *, int, enum insn_mode);
insn_attr_t c_inat_get_opcode_attribute(insn_byte_t), c_inat_get_escape_attribute(insn_byte_t, int, insn_attr_t),
    c_inat_get_group_attribute(insn_byte_t, int, insn_attr_t), c_inat_get_avx_attribute(insn_byte_t, insn_byte_t, insn_byte_t),
    c_inat_get_xop_attribute(insn_byte_t, insn_byte_t);
int c_inat_get_last_prefix_id(insn_byte_t);

static unsigned long long fails, checks;
static int poison;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)

static uint64_t rs;
static uint64_t rnd(void) { uint64_t z = (rs += 0x9e3779b97f4a7c15ULL); z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }

static unsigned long long st_ok, st_len[16], st_vex, st_rex2, st_emul, st_xop, st_evex, st_grp, st_imm2, st_esc3, st_enodata, st_einval;
static unsigned char *page_end;     /* 16 bytes before the guard page */
static unsigned char *put(const unsigned char *b, int len)
{
	unsigned char *p = page_end - len;
	memcpy(p, b, len);
	return p;
}

/* ---- inat ---- */
static insn_attr_t seen[1 << 16]; static unsigned nseen;
static void add(insn_attr_t a) { for (unsigned i = 0; i < nseen; i++) if (seen[i] == a) return; if (nseen < 1 << 16) seen[nseen++] = a; }

static void tinat(void)
{
	for (int o = 0; o < 256; o++) {
		insn_attr_t a = c_inat_get_opcode_attribute(o), b = inat_get_opcode_attribute(o);
		checks++; if (poison && o == 0x0f) b ^= 1;
		if (a != b) FAIL("opcode_attr %#x c=%#x rs=%#x\n", o, a, b);
		if (c_inat_get_last_prefix_id(o) != inat_get_last_prefix_id(o)) FAIL("last_prefix_id %#x\n", o);
		add(a);
	}
	for (unsigned i = 0; i < nseen; i++) {          /* closure over escape/group results */
		for (int o = 0; o < 256; o++) for (int l = 0; l < 4; l++) {
			add(c_inat_get_escape_attribute(o, l, seen[i]));
			add(c_inat_get_group_attribute(o, l, seen[i]));
		}
	}
	for (unsigned i = 0; i < nseen; i++)
		for (int o = 0; o < 256; o++) for (int l = 0; l < 4; l++) {
			insn_attr_t a = c_inat_get_escape_attribute(o, l, seen[i]), b = inat_get_escape_attribute(o, l, seen[i]);
			insn_attr_t c = c_inat_get_group_attribute(o, l, seen[i]), d = inat_get_group_attribute(o, l, seen[i]);
			checks += 2;
			if (a != b) FAIL("escape o=%#x l=%d attr=%#x c=%#x rs=%#x\n", o, l, seen[i], a, b);
			if (c != d) FAIL("group m=%#x l=%d attr=%#x c=%#x rs=%#x\n", o, l, seen[i], c, d);
		}
	for (int m = 0; m < 48; m++) for (int p = 0; p < 6; p++) for (int o = 0; o < 256; o++) {
		insn_attr_t a = c_inat_get_avx_attribute(o, m, p), b = inat_get_avx_attribute(o, m, p);
		checks++; if (a != b) FAIL("avx o=%#x m=%d p=%d c=%#x rs=%#x\n", o, m, p, a, b);
	}
	for (int m = 0; m < 48; m++) for (int o = 0; o < 256; o++) {
		insn_attr_t a = c_inat_get_xop_attribute(o, m), b = inat_get_xop_attribute(o, m);
		checks++; if (a != b) FAIL("xop o=%#x m=%d c=%#x rs=%#x\n", o, m, a, b);
	}
}

/* ---- decode ---- */
static void cmp_struct(const char *what, const unsigned char *in, int len, int mode, int ra, int rb, struct insn *a, struct insn *b)
{
	checks++;
	if (poison && len == 3 && in[0] == 0x0f && in[1] == 0x1f) rb++;
	if (ra != rb || memcmp(a, b, sizeof *a)) {
		FAIL("%s MISMATCH mode=%d len=%d bytes=", what, mode, len);
		for (int i = 0; i < len && i < 15; i++) fprintf(stderr, "%02x ", in[i]);
		fprintf(stderr, "c=%d rs=%d len(c/rs)=%d/%d opc=%02x/%02x attr=%#x/%#x\n", ra, rb, a->length, b->length,
			a->opcode.bytes[0], b->opcode.bytes[0], a->attr, b->attr);
	}
}

static void tdecode(const unsigned char *bytes, int len, int mode)
{
	struct insn a, b;
	unsigned char *p = put(bytes, len);
	/* poison the structs differently: insn_init memsets, so the result must not depend on it */
	memset(&a, 0x11, sizeof a); memset(&b, 0x22, sizeof b);
	int ra = c_insn_decode(&a, p, len, mode == 1 ? INSN_MODE_64 : INSN_MODE_32);
	int rb = insn_decode(&b, p, len, (enum insn_mode)mode);
	cmp_struct("decode", bytes, len, mode, ra, rb, &a, &b);
	if (ra == 0) { st_ok++; st_len[a.length & 15]++; } else if (ra == -61) st_enodata++; else st_einval++;
	st_vex += a.vex_prefix.nbytes == 2 || a.vex_prefix.nbytes == 3; st_evex += a.vex_prefix.nbytes == 4;
	st_rex2 += a.rex_prefix.nbytes == 2; st_emul += a.emulate_prefix_size != 0; st_esc3 += a.opcode.nbytes == 3;
}

static void tstages(const unsigned char *bytes, int len, int mode)
{
	struct insn a, b;
	unsigned char *p = put(bytes, len);
	c_insn_init(&a, p, len, mode);
	insn_init(&b, p, len, mode);
	int n = 1 + rnd() % 7;
	while (n--) {
		int ra, rb, k = rnd() % 8;
		switch (k) {
		case 0: ra = c_insn_get_prefixes(&a); rb = insn_get_prefixes(&b); break;
		case 1: ra = c_insn_get_opcode(&a); rb = insn_get_opcode(&b); break;
		case 2: ra = c_insn_get_modrm(&a); rb = insn_get_modrm(&b); break;
		case 3: ra = c_insn_get_sib(&a); rb = insn_get_sib(&b); break;
		case 4: ra = c_insn_get_displacement(&a); rb = insn_get_displacement(&b); break;
		case 5: ra = c_insn_get_immediate(&a); rb = insn_get_immediate(&b); break;
		case 6: ra = c_insn_get_length(&a); rb = insn_get_length(&b); break;
		default: ra = c_insn_rip_relative(&a); rb = insn_rip_relative(&b); break;
		}
		cmp_struct("stage", bytes, len, mode, ra, rb, &a, &b);
	}
}

static const unsigned char pfx[] = { 0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65 };
static const unsigned char xen[] = { 0x0f, 0x0b, 0x78, 0x65, 0x6e }, kvm[] = { 0x0f, 0x0b, 0x6b, 0x76, 0x6d };

static int gen(unsigned char *o)
{
	int n = 0;
	int style = rnd() % 10;
	if (style == 2) {                         /* buffer longer than MAX_INSN_SIZE: a run of one prefix, then something */
		int run = 10 + rnd() % 10, k;
		unsigned char pb = pfx[rnd() % sizeof pfx];
		for (k = 0; k < run; k++) o[n++] = pb;
		while (n < 32) o[n++] = rnd();
		return 16 + rnd() % 17;
	}
	if (style == 0) { n = 1 + rnd() % 15; for (int i = 0; i < n; i++) o[i] = rnd(); return n; }
	if (style == 1 && n == 0) { memcpy(o, (rnd() & 1) ? xen : kvm, 5); n = 5; }
	int k = rnd() % 6;
	while (k-- && n < 6) o[n++] = (rnd() % 4) ? pfx[rnd() % sizeof pfx] : (unsigned char)rnd();
	switch (rnd() % 9) {
	case 0: o[n++] = 0x40 | (rnd() & 15); break;
	case 1: o[n++] = 0xc5; o[n++] = rnd(); break;
	case 2: o[n++] = 0xc4; o[n++] = rnd(); o[n++] = rnd(); break;
	case 3: o[n++] = 0x62; o[n++] = rnd(); o[n++] = rnd(); o[n++] = rnd(); break;
	case 4: o[n++] = 0x8f; o[n++] = rnd(); o[n++] = rnd(); break;
	case 5: o[n++] = 0xd5; o[n++] = rnd(); break;
	default: break;
	}
	switch (rnd() % 6) {
	case 0: o[n++] = 0x0f; o[n++] = 0x38; break;
	case 1: o[n++] = 0x0f; o[n++] = 0x3a; break;
	case 2: o[n++] = 0x0f; break;
	default: break;
	}
	while (n < 15) o[n++] = (rnd() % 3) ? (unsigned char)rnd() : "\x00\x05\x04\x24\xc0\x80"[rnd() % 6];
	return (rnd() % 3) ? 15 : (int)(1 + rnd() % 15);
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0, nsh = argc > 2 ? atoi(argv[2]) : 1;
	unsigned long long nrand = getenv("X86INSN_NRAND") ? strtoull(getenv("X86INSN_NRAND"), 0, 0) : 100000000ULL;
	poison = getenv("X86INSN_PROVE_CAN_FAIL") != 0;
	int failfast = getenv("X86INSN_FAILFAST") != 0;
	long pg = sysconf(_SC_PAGESIZE);
	unsigned char *m = mmap(0, 2 * pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	mprotect(m + pg, pg, PROT_NONE);
	page_end = m + pg;
	rs = 0xabcdef12345ULL * (shard + 1);

	if (shard == 0) tinat();
	unsigned char b[16];
	for (int mode = 0; mode < 2; mode++) {
		for (unsigned x = shard; x < (1u << 24); x += nsh) {      /* all 1..3 byte sequences, tail derived */
			uint64_t h = x * 0x9e3779b97f4a7c15ULL;
			b[0] = x; b[1] = x >> 8; b[2] = x >> 16;
			for (int i = 3; i < 15; i++) b[i] = (h >> (4 * i)) & 3 ? (h >> (5 * i)) : "\x00\x05\x04\x24\xc0\x80"[(h >> i) % 6];
			tdecode(b, 15, mode);
			tdecode(b, 3, mode);
			if (failfast && fails) goto done;
		}
		for (unsigned x = shard; x < 65536; x += nsh) {          /* exact short buffers */
			b[0] = x; b[1] = x >> 8;
			for (int l = 0; l <= 2; l++) tdecode(b, l, mode);
		}
	}
	for (unsigned long long i = 0; i < nrand; i++) {
		unsigned char s[40];
		int len = gen(s);
		int mode = rnd() & 1;
		tdecode(s, len, mode);
		if (!(i & 3)) tstages(s, len, mode);
		if (failfast && fails) break;
	}
done:
	printf("shard %u/%u: %llu checks, %llu failures\n", shard, nsh, checks, fails);
	if (getenv("X86INSN_STATS")) { printf("  ok %llu enodata %llu einval %llu | vex %llu evex %llu rex2 %llu emul %llu 3byte-opcode %llu | lengths:", st_ok, st_enodata, st_einval, st_vex, st_evex, st_rex2, st_emul, st_esc3); for (int i = 1; i < 16; i++) printf(" %d:%llu", i, st_len[i]); printf("\n"); }
	return fails != 0;
}
