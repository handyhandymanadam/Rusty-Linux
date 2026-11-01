/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_KERNEL_H
#define _SHIM_VSPRINTF_LINUX_KERNEL_H
/*
 * Deliberately NOT `#include <stdio.h>`: glibc's own <stdio.h> `#define`s
 * `vsscanf`/`sscanf` to `__isoc99_vsscanf`/`__isoc99_sscanf` (source-level
 * redirect macros, include/bits/stdio2-ish machinery) -- since a plain
 * `#define` always wins over an earlier `-D` command-line macro, THAT
 * definition would silently override this harness's own
 * `-Dvsscanf=ref_vsscanf`/`-Dsscanf=ref_sscanf` (etc.) renames, making
 * both the REF and "mine" arms actually emit `__isoc99_vsscanf` regardless
 * of the requested rename -- a real duplicate-symbol collision this
 * harness hit on its first run. Declaring only the two symbols actually
 * used (`fprintf`, `stderr`) avoids pulling in that redirect at all.
 */
#ifndef _STDIO_H
extern int fprintf(void *stream, const char *format, ...);
extern void *stderr;
#endif
#include <string.h>
#include <limits.h>
#include <linux/hex.h>
#include <linux/err.h>

#define IS_ENABLED(x) (0)
#define likely(x) (x)
#define unlikely(x) (x)
#define noinline_for_stack
#define noinline
#define __init
#define __ro_after_init
#define __read_mostly
#define __initdata
#define __force
#define __printf(a, b)
#define __scanf(a, b)
#define fallthrough do {} while (0)

#define WARN_ONCE(cond, fmt, ...) ({ int __r = !!(cond); if (__r) fprintf(stderr, "WARN_ONCE: " fmt, ##__VA_ARGS__); __r; })
#define WARN_ON_ONCE(cond) ({ int __r = !!(cond); if (__r) fprintf(stderr, "WARN_ON_ONCE(" #cond ")\n"); __r; })

#define pr_info(fmt, ...) ((void)0)
#define pr_warn(fmt, ...) ((void)0)

#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)

#define __diag_push()
#define __diag_pop()
#define __diag_ignore(compiler, option, warning, why)

/* va_format() (%pV) is permanently C but unexercised by this harness's
 * corpus (this file never constructs a `va_list` -- see vsprintf_rs.rs's
 * own module doc). Minimal stand-in. */
struct va_format {
	const char *fmt;
	va_list *va;
};

#define BIT(x) (1UL << (x))
#define clamp(val, lo, hi) ((val) >= (hi) ? (hi) : ((val) <= (lo) ? (lo) : (val)))

/* rust_fmt_argument (%pA) is Rust-only by upstream's own doc comment --
 * "Do *not* use it from C" -- never reached by this harness's corpus.
 * Declared only so pointer()'s dispatch switch compiles. */
char *rust_fmt_argument(char *buf, char *end, const void *ptr);

/*
 * skip_spaces() -- UNLIKE port/test/vsprintf's copy of this header
 * (a `static inline` space-only stand-in, fine there since that
 * harness never exercises vsscanf()'s whitespace handling at all),
 * THIS harness's corpus specifically drives tabs/newlines through
 * vsscanf()'s whitespace-skipping (its own literal-match and numeric-
 * prefix logic both call skip_spaces()), so a real, correct
 * (isspace()-based) definition matters here -- a space-only stand-in
 * would make the REF arm itself diverge from real upstream behavior,
 * not just from "mine". Real definition lives in stubs.c (shared by
 * both C arms AND declared `extern "C"` by vsprintf_scan_rs.rs), so
 * only a prototype is needed here.
 */
char *skip_spaces(const char *str);
#define _tolower(c) ((c) | 0x20)
#define isodigit(c) ((c) >= '0' && (c) <= '7')
#define DECLARE_BITMAP(name, bits) unsigned long name[((bits) + 63) / 64]
static inline void __set_bit(int nr, unsigned long *addr) { addr[nr / 64] |= (1UL << (nr % 64)); }
static inline void __clear_bit(int nr, unsigned long *addr) { addr[nr / 64] &= ~(1UL << (nr % 64)); }
static inline int test_bit(int nr, const unsigned long *addr) { return (addr[nr / 64] >> (nr % 64)) & 1; }
static inline void bitmap_complement(unsigned long *dst, const unsigned long *src, unsigned int nbits)
{
	unsigned int i;
	for (i = 0; i < (nbits + 63) / 64; i++)
		dst[i] = ~src[i];
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define PTR_ALIGN(p, a) ((typeof(p))ALIGN((unsigned long)(p), (a)))
#define __aligned(x) __attribute__((aligned(x)))
#define BITS_PER_LONG 64
#define BITS_PER_LONG_LONG 64

#define do_div(n, base) \
	({ \
		unsigned int __rem = (unsigned int)((n) % (base)); \
		(n) = (n) / (base); \
		__rem; \
	})
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))

static inline unsigned long hash_long(unsigned long val, unsigned int bits)
{
	/* hash_64/hash_64_generic, BITS_PER_LONG==64 arm -- this project's
	 * only target, same as vsprintf_rs.rs's own `hash_long_32`. */
	const unsigned long long golden_ratio_64 = 0x61C8864680B583EBULL;
	return (unsigned long)((val * golden_ratio_64) >> (64 - bits));
}

static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	for (; offset < size; offset++)
		if ((addr[offset / BITS_PER_LONG] >> (offset % BITS_PER_LONG)) & 1)
			return offset;
	return size;
}
static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size, unsigned long offset)
{
	for (; offset < size; offset++)
		if (!((addr[offset / BITS_PER_LONG] >> (offset % BITS_PER_LONG)) & 1))
			return offset;
	return size;
}
#define for_each_set_bitrange(b, e, addr, size)			\
	for ((b) = 0;						\
	     (b) = find_next_bit((addr), (size), b),		\
	     (e) = find_next_zero_bit((addr), (size), (b) + 1),	\
	     (b) < (size);					\
	     (b) = (e) + 1)

/* include/linux/tracepoint-defs.h, unchanged. */
struct trace_print_flags {
	unsigned long mask;
	const char *name;
};

#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_wmb() do {} while (0)
#define smp_rmb() do {} while (0)

#define early_param(str, fn) /* no boot-param registry in this harness */
#define subsys_initcall(fn) /* no init-call machinery in this harness */

static inline void get_random_bytes(void *buf, int len)
{
	/* Deterministic (not actually random) -- filled_random_ptr_key's
	 * gate is what's under test, not RNG quality. */
	memset(buf, 0x42, len);
}

#endif
