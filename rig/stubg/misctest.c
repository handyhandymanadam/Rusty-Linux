// Differential test for misc.c's parse_elf() and handle_relocations(): the ORIGINAL C (the pristine misc.c compiled with
// kbuild's flags, symbol prefix c_) against misc_rs.rs (prefix rs_). Built/run by rig/stubg/run-misc.sh.
// Each case: a random synthetic image in an arena, run C on it, snapshot, restore the initial bytes, run Rust on it at the
// SAME address, compare the whole arena, the return value and the event log (every __putstr text, every error() text,
// malloc/free calls of the Rust side vs the heap state of the C side).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include <sys/mman.h>

static char ev[4096];
#define EV(...) do { size_t l = strlen(ev); snprintf(ev + l, sizeof ev - l, __VA_ARGS__); } while (0)
static jmp_buf jb;
#define FAKES(P) \
void P##__putstr(const char *s) { EV("[%s]", s); } \
void P##error(char *m) { EV("ERR{%s}", m); longjmp(jb, 1); } \
void *P##memcpy(void *a, const void *b, size_t n) { return memcpy(a, b, n); } \
void *P##memmove(void *a, const void *b, size_t n) { return memmove(a, b, n); } \
void *P##memset(void *a, int c, size_t n) { return memset(a, c, n); } \
int P##memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
FAKES(c_) FAKES(rs_)

/* constants the Rust reads (misc_cfg.c); the same numbers as the voffset.h given to the C (see run-misc.sh) */
const unsigned long rs_misc_load_physical_addr = 0x1000000UL;
const unsigned long rs_misc_start_kernel_map = 0xffffffff80000000UL;
const unsigned long rs_misc_text_to_bss_start = 0x8000UL;

/* from the C object (wrapper in run-misc.sh) */
void *c_malloc(int); void c_free(void *);
extern long c_free_mem_ptr, c_free_mem_end_ptr;
size_t c_ref_parse_elf(void *); void c_ref_handle_relocations(void *, unsigned long, unsigned long);
unsigned long c_ref_heap_state(void);
void c_ref_heap_reset(void);
/* the Rust's malloc/free go to the C ones (same code), logged */
void *rs_malloc(int n) { return c_malloc(n); }
void rs_free(void *p) { c_free(p); }
size_t rs_parse_elf(void *); void rs_handle_relocations(void *, unsigned long, unsigned long);

static uint64_t s = 88172645463325252ULL;
static uint64_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s; }
static unsigned long checks, fails;
#define W16(p, o, v) (*(uint16_t *)((char *)(p) + (o)) = (v))
#define W32(p, o, v) (*(uint32_t *)((char *)(p) + (o)) = (v))
#define W64(p, o, v) (*(uint64_t *)((char *)(p) + (o)) = (v))

#define ARENA (256 * 1024)
static char heap[1 << 16];

struct res { unsigned long ret; char ev[4096]; unsigned long heap; char *mem; };

static void run_elf(int rust, char *a, struct res *r)
{
	ev[0] = 0; c_free_mem_ptr = (long)heap; c_free_mem_end_ptr = (long)heap + sizeof heap; c_ref_heap_reset();
	r->ret = ~0UL;
	if (!setjmp(jb)) r->ret = rust ? rs_parse_elf(a) : c_ref_parse_elf(a);
	strcpy(r->ev, ev); r->heap = c_ref_heap_state();
	memcpy(r->mem, a, ARENA);
}
static void run_rel(int rust, char *a, unsigned long len, unsigned long va, struct res *r)
{
	ev[0] = 0;
	if (!setjmp(jb)) { if (rust) rs_handle_relocations(a, len, va); else c_ref_handle_relocations(a, len, va); }
	strcpy(r->ev, ev); r->heap = 0; r->ret = 0;
	memcpy(r->mem, a, ARENA);
}
static void compare(const char *what, long i, const char *a, const char *init, struct res *c, struct res *rs)
{
	checks++;
	if (c->ret != rs->ret || strcmp(c->ev, rs->ev) || c->heap != rs->heap || memcmp(c->mem, rs->mem, ARENA)) {
		fails++;
		if (fails < 6) printf("DIFF %s case %ld: ret %lx/%lx heap %lx/%lx\n C : %s\n RS: %s\n memdiff=%d\n", what, i, c->ret, rs->ret, c->heap, rs->heap, c->ev, rs->ev, memcmp(c->mem, rs->mem, ARENA) != 0);
	}
}

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 100000;
	unsigned long stat_err = 0, stat_ok = 0, stat_rel = 0, stat_norel = 0, stat_relerr = 0;
	/* parse_elf arena at LOAD_PHYSICAL_ADDR: also valid for the non-relocatable arm (dest = p_paddr is absolute) */
	char *A = mmap((void *)0x1000000UL, ARENA, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	/* relocation arena ABOVE 4 GiB so that delta/map wrap non-trivially */
	char *H = mmap((void *)0x123400000000UL, ARENA, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (A == MAP_FAILED || H == MAP_FAILED) { puts("mmap failed"); return 2; }
	char *init = malloc(ARENA); struct res c = { .mem = malloc(ARENA) }, rs = { .mem = malloc(ARENA) };
	static const uint32_t ptypes[] = { 1, 1, 1, 1, 0, 4, 0x6474e551, 2 };
	static const uint64_t aligns[] = { 0x200000, 0x200000, 0x200000, 0x400000, 0x200000, 0x200000, 0x200000, 0x200000 * 5 };
	static const uint64_t badaligns[] = { 0x1000, 1, 0x200001, 0x100000 };
	for (long i = 0; i < n; i++) {
		/* ---- parse_elf ---- */
		for (int k = 0; k < ARENA; k += 8) *(uint64_t *)(A + k) = rnd();
		memset(A, 0, 64);
		memcpy(A, "\177ELF", 4);
		if (rnd() % 10 == 0) A[rnd() % 4] ^= 1 << (rnd() % 8);
		unsigned phnum = rnd() % 9; if (rnd() % 40 == 0) phnum = rnd() % 1000;
		unsigned long phoff = 64 + (rnd() % 64);
		if (rnd() % 20 == 0) phoff = rnd() % (ARENA - 56 * 9);
		W64(A, 24, rnd()); W64(A, 32, phoff); W16(A, 56, phnum);
		if (phnum * 56 + phoff > ARENA) phnum = 0, W16(A, 56, 0);
		for (unsigned p = 0; p < phnum; p++) {
			char *ph = A + phoff + 56 * p;
			uint64_t fs = rnd() % 2048, src = rnd() % (ARENA - 2048), dst = rnd() % (ARENA - 2048);
			if (rnd() % 8 == 0) fs = 0;
			W32(ph, 0, ptypes[rnd() % 8]); W32(ph, 4, rnd()); W64(ph, 8, src); W64(ph, 16, rnd());
			W64(ph, 24, 0x1000000UL + dst); W64(ph, 32, fs); W64(ph, 40, rnd()); W64(ph, 48, rnd() % 40 == 0 ? badaligns[rnd() % 4] : aligns[rnd() % 8]);
		}
		memcpy(init, A, ARENA);
		run_elf(0, A, &c);
		memcpy(A, init, ARENA);
		run_elf(1, A, &rs);
		compare("parse_elf", i, A, init, &c, &rs);
		if (strstr(c.ev, "ERR")) stat_err++; else stat_ok++;
		memcpy(A, init, ARENA);
#ifdef HAVE_RELOCS
		/* ---- handle_relocations ---- */
		for (int k = 0; k < ARENA; k += 8) *(uint64_t *)(H + k) = rnd();
		unsigned n32 = rnd() % 30, n64 = rnd() % 30; int bad = rnd() % 12 == 0;
		unsigned long K = 0x8000, len = K + 16 + 4 * (n32 + n64 + 2) + 4 * (rnd() % 8), pos = len - 4;
		for (unsigned k = 0; k < n32; k++, pos -= 4) {
			uint64_t off = rnd() % (K + 1); if (off > K - 4 && rnd() % 4) off = K - 4;
			int32_t e = (int32_t)(0x81000000UL + off); if (bad && rnd() % (n32 + 1) == 0) e = (int32_t)rnd() | 1;
			*(int32_t *)(H + pos) = e;
		}
		*(int32_t *)(H + pos) = 0; pos -= 4;
		for (unsigned k = 0; k < n64; k++, pos -= 4) {
			uint64_t off = rnd() % (K + 1); if (off > K - 8 && rnd() % 4) off = K - 8;
			int32_t e = (int32_t)(0x81000000UL + off); if (bad && rnd() % (n64 + 1) == 0) e = (int32_t)rnd() | 1;
			*(int32_t *)(H + pos) = e;
		}
		*(int32_t *)(H + pos) = 0;
		unsigned long va = 0x1000000UL; unsigned m = rnd() % 8;
		if (m) va = 0x1000000UL + (rnd() % 512) * 0x200000UL;
		if (m == 7) va = rnd();
		memcpy(init, H, ARENA);
		run_rel(0, H, len, va, &c);
		memcpy(H, init, ARENA);
		run_rel(1, H, len, va, &rs);
		compare("handle_relocations", i, H, init, &c, &rs);
		if (strstr(c.ev, "ERR")) stat_relerr++; else if (va == 0x1000000UL) stat_norel++; else stat_rel++;
		memcpy(H, init, ARENA);
#endif
	}
	printf("parse_elf: %lu ok-path cases, %lu error cases", stat_ok, stat_err);
#ifdef HAVE_RELOCS
	printf("; handle_relocations: %lu applied, %lu no-reloc, %lu error", stat_rel, stat_norel, stat_relerr);
#endif
	printf("\nchecks=%lu differences=%lu\n", checks, fails);
	return fails != 0;
}
