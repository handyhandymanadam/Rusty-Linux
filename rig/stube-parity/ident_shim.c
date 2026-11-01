/* Userspace shim for ident_cmp.rs: the globals both the original C and the Rust port expect, and a
 * page allocator over an arena (so both builds allocate identically). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
unsigned int __pgtable_l5_enabled, pgdir_shift = 39, ptrs_per_p4d = 1;
unsigned char *boot_params_ptr; int spurious_nmi_count;
unsigned long test_cr3;
__asm__(".bss\n.balign 4096\n.globl _head\n_head:\n.skip 20480\n.globl _end\n_end:\n.skip 1\n.text\n");   /* a 20 KiB 'image' */
unsigned char _pgtable[32 * 4096] __attribute__((aligned(4096)));   /* BOOT_PGT_SIZE */
#include <setjmp.h>
static jmp_buf jb;
/* error() never returns in the stub; here it unwinds to the guarded_* caller so the test can compare
 * "both called error()" as an outcome (the Rust frames skipped have no destructors) */
void error(char *m) { longjmp(jb, 1); }
int guarded_add(void (*fn)(unsigned long, unsigned long), unsigned long a, unsigned long b)
{ if (setjmp(jb)) return 1; fn(a, b); return 0; }
int guarded_init(void (*fn)(unsigned char *), unsigned char *a)
{ if (setjmp(jb)) return 1; fn(a); return 0; }
int guarded_set(int (*fn)(unsigned long), unsigned long a, int *out)
{ if (setjmp(jb)) return 1; *out = fn(a); return 0; }
void __putstr(const char *s) {} void __puthex(unsigned long v) {}
unsigned long test_cmdline;
unsigned long get_cmd_line_ptr(void) { return test_cmdline; }

/* arena allocator: context -> {base, pages, used} */
struct arena { unsigned char *base; unsigned long pages, used; };
void *arena_alloc(void *ctx)
{
	struct arena *a = ctx;
	if (a->used >= a->pages) return NULL;
	return a->base + 4096 * a->used++;
}
