// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/lib/vsprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 * Retained-C half of the Rust port, lib/vsprintf_rs.rs. What stays here and
 * why:
 *
 *  - vsnprintf()/vbin_printf()/vsscanf() (and the trivial va_list wrappers
 *    around vsnprintf: vscnprintf/snprintf/scnprintf/vsprintf/sprintf) touch
 *    va_arg directly and cannot move -- core::ffi::VaList is unstable on the
 *    pinned toolchain and not in this project's rust_allowed_features. Both
 *    vsnprintf() and vbin_printf() call back into vsprintf_rs.rs's
 *    vsprintf_rs_format_decode()/vsprintf_rs_number()/
 *    vsprintf_rs_set_field_width()/vsprintf_rs_set_precision()/
 *    vsprintf_rs_string()/vsprintf_rs_convert_num_spec()/
 *    vsprintf_rs_check_pointer_msg()/vsprintf_rs_pointer() for everything
 *    that used to be a same-translation-unit static call.
 *  - 8 %p handlers vsprintf_rs.rs's own module doc names as deferred
 *    (dentry/file/bdev/device_node/fwnode/time+date/clock/page_flags),
 *    plus va_format (struct va_format's va_list dependency), stay here,
 *    renamed vsprintf_c_* to match the extern declarations vsprintf_rs.rs
 *    already has for them. Each is otherwise byte-identical to the
 *    pristine source, with its own now-Rust-side helper calls
 *    (check_pointer/string/string_nocheck/widen_string/error_string/number/
 *    format_flags/ptr_to_id/pointer) redirected to the matching
 *    vsprintf_rs_* entry point.
 *  - restricted_pointer() (%pK) itself moved to vsprintf_rs.rs (its own
 *    checkpoint, the pure/impure split -- see that file's module doc).
 *    Only in_hardirq()/in_serving_softirq()/in_nmi() (real preempt-count
 *    macros) and the has_capability_noaudit()/uid_eq()/gid_eq() credential
 *    check (real struct cred/LSM machinery) stay here, as two tiny
 *    boolean-returning helpers Rust calls in a specific order it enforces,
 *    not these two functions themselves.
 *  - simple_strntoull/simple_strtoull/simple_strtoul/simple_strntoul/
 *    simple_strtol/simple_strntoll/simple_strtoll stay here UNCHANGED --
 *    an independent, low-risk follow-up port, not touched this pass.
 *  - The boot-param/init machinery (hash_pointers_finalize/
 *    hash_pointers_mode_parse/no_hash_pointers_enable/
 *    debug_boot_weak_hash_enable/fill_ptr_key/vsprintf_init_hashval) is
 *    one-time setup, unchanged, and still owns no_hash_pointers/
 *    filled_random_ptr_key/ptr_key/debug_boot_weak_hash -- three of those
 *    four LOSE their `static` here (debug_boot_weak_hash, filled_random_
 *    ptr_key, ptr_key) so vsprintf_rs.rs's `extern "C" static` declarations
 *    can link against them; deliberate divergence from upstream, recorded
 *    here so it doesn't get "fixed" back to static later.
 *
 * Deleted entirely (moved to vsprintf_rs.rs, see its own module doc for the
 * exact function list): decpair, the put_dec family, num_to_str, number,
 * special_hex_number, move_right/widen_string/string_nocheck/err_ptr/
 * error_string/check_pointer_msg/check_pointer/string/pointer_string,
 * __ptr_to_hashval/ptr_to_hashval/default_pointer/ptr_to_id, symbol_string,
 * hex_range/resource_string/range_string/resource_or_range, hex_string/
 * bitmap_string/bitmap_list_string/mac_address_string, the whole ip4/ip6
 * address family, escaped_string, uuid_string, netdev_bits/fourcc_string/
 * address_val, format_flags/flags_string, spec_flag/set_field_width/
 * set_precision/convert_num_spec, format_decode, pointer(). See
 * lib/vsprintf_rs.rs's own module doc for the full reasoning and the
 * verification plan both were reviewed against.
 */

#include <linux/stdarg.h>
#include <linux/build_bug.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/errname.h>
#include <linux/module.h>	/* for KSYM_SYMBOL_LEN */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/rtc.h>
#include <linux/sprintf.h>
#include <linux/time.h>
#include <linux/uuid.h>
#include <linux/of.h>
#include <net/addrconf.h>
#include <linux/siphash.h>
#include <linux/compiler.h>
#include <linux/property.h>
#include <linux/notifier.h>
#ifdef CONFIG_BLOCK
#include <linux/blkdev.h>
#endif

#include "../mm/internal.h"	/* For the trace_print_flags arrays */

#include <asm/page.h>		/* for PAGE_SIZE */
#include <asm/byteorder.h>	/* cpu_to_le16 */
#include <linux/unaligned.h>

#include <linux/string_helpers.h>
#include "kstrtox.h"

/*
 * struct printf_spec/enum format_state/struct fmt -- moved up here from
 * their original spots further down (`format_decode()`'s own vicinity,
 * upstream) because every `vsprintf_rs_*`/`vsprintf_c_*` prototype below
 * needs the COMPLETE type, not a forward declaration: Clang's
 * `-Wvisibility` (a hard error under this build) rejects a function
 * prototype that passes an as-yet-incomplete struct BY VALUE. Otherwise
 * byte-identical to upstream.
 */
#define SIGN	1		/* unsigned/signed */
#define LEFT	2		/* left justified */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define ZEROPAD	16		/* pad with zero, must be 16 == '0' - ' ' */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */

static_assert(ZEROPAD == ('0' - ' '));
static_assert(SMALL == ('a' ^ 'A'));

enum format_state {
	FORMAT_STATE_NONE, /* Just a string part */
	FORMAT_STATE_NUM,
	FORMAT_STATE_WIDTH,
	FORMAT_STATE_PRECISION,
	FORMAT_STATE_CHAR,
	FORMAT_STATE_STR,
	FORMAT_STATE_PTR,
	FORMAT_STATE_PERCENT_CHAR,
	FORMAT_STATE_INVALID,
};

struct printf_spec {
	unsigned char	flags;		/* flags to number() */
	unsigned char	base;		/* number base, 8, 10 or 16 only */
	short		precision;	/* # of digits/chars */
	int		field_width;	/* width of output field */
} __packed;
static_assert(sizeof(struct printf_spec) == 8);

#define FIELD_WIDTH_MAX ((1 << 23) - 1)
#define PRECISION_MAX ((1 << 15) - 1)

struct fmt {
	const char *str;
	unsigned char state;	// enum format_state
	unsigned char size;	// size of numbers
};

/*
 * vsscanf()'s per-specifier classification, returned by value from
 * lib/vsprintf_scan_rs.rs's vsprintf_scan_rs_next() -- see that file's
 * ScanKind/ScanSpec (#[repr(u8)]/#[repr(C)]) and its module doc for the
 * full design. Field order/types must match ScanSpec exactly; C and
 * Rust compute identical natural-alignment layout from that alone, same
 * as struct printf_spec/struct fmt above, so no `__packed` or explicit
 * offsets are needed here (verified by the size assert below).
 */
enum scan_kind {
	SCAN_DONE = 0,
	SCAN_CONTINUE = 1,
	SCAN_NEED_N = 2,
	SCAN_NEED_C = 3,
	SCAN_NEED_S = 4,
	SCAN_NEED_BRACKET = 5,
	SCAN_NEED_NUMERIC = 6,
};

struct scan_spec {
	unsigned char kind;	// enum scan_kind
	bool stop;
	unsigned char qualifier;
	bool is_sign;
	unsigned int base;
	short field_width;
	unsigned long long set[4];
};
static_assert(sizeof(struct scan_spec) == 48);

/*
 * Entry points into lib/vsprintf_rs.rs. `struct printf_spec`/`struct fmt`
 * are passed by value across this boundary -- vsprintf_rs.rs's
 * `PrintfSpec`/`Fmt` are `#[repr(C, packed)]`/`#[repr(C)]` mirrors with a
 * `static_assert`-pinned layout, verified to match.
 */
char *vsprintf_rs_pointer(const char *fmt, char *buf, char *end, const void *ptr,
			   struct printf_spec spec);
struct fmt vsprintf_rs_format_decode(struct fmt fmt, struct printf_spec *spec);
char *vsprintf_rs_number(char *buf, char *end, unsigned long long num, struct printf_spec spec);
void vsprintf_rs_set_field_width(struct printf_spec *spec, int width);
void vsprintf_rs_set_precision(struct printf_spec *spec, int prec);
char *vsprintf_rs_string(char *buf, char *end, const char *s, struct printf_spec spec);
unsigned long long vsprintf_rs_convert_num_spec(unsigned int val, int size, struct printf_spec spec);
const char *vsprintf_rs_check_pointer_msg(const void *ptr);
int vsprintf_rs_check_pointer(char **buf, char *end, const void *ptr, struct printf_spec spec);
char *vsprintf_rs_widen_string(char *buf, int n, char *end, struct printf_spec spec);
char *vsprintf_rs_error_string(char *buf, char *end, const char *s, struct printf_spec spec);
char *vsprintf_rs_string_nocheck(char *buf, char *end, const char *s, struct printf_spec spec);
char *vsprintf_rs_format_flags(char *buf, char *end, unsigned long flags,
				const struct trace_print_flags *names);
char *vsprintf_rs_ptr_to_id(char *buf, char *end, const void *ptr, struct printf_spec spec);

/*
 * Entry points into lib/vsprintf_scan_rs.rs -- vsscanf()'s Rust half.
 * `set` in vsprintf_scan_rs_consume_bracket() is `struct scan_spec`'s
 * `set` field (an array-typed struct member), which decays to a
 * pointer to its first element here, matching the Rust side's plain
 * `*const u64` parameter.
 */
struct scan_spec vsprintf_scan_rs_next(const char **fmt, const char **str, const char *buf);
void vsprintf_scan_rs_consume_c(const char **str, short field_width, char *dst);
void vsprintf_scan_rs_consume_s(const char **str, short field_width, char *dst);
void vsprintf_scan_rs_consume_bracket(const char **str, short field_width,
				       const unsigned long long *set, char *dst);

/*
 * Prototypes for every renamed vsprintf_c_* entry point Rust calls into --
 * required by -Wmissing-prototypes (a non-static function with no prior
 * declaration is an error under this build), and each definition further
 * down keeps its own doc comment explaining what it is and why it's here.
 */
void vsprintf_c_format_decode_invalid_warn(int c);
bool vsprintf_c_in_irq_context(void);
bool vsprintf_c_restricted_pointer_cred_ok(void);
char *vsprintf_c_dentry_name(char *buf, char *end, const struct dentry *d,
			      struct printf_spec spec, const char *fmt);
char *vsprintf_c_file_dentry_name(char *buf, char *end, const struct file *f,
				   struct printf_spec spec, const char *fmt);
#ifdef CONFIG_BLOCK
char *vsprintf_c_bdev_name(char *buf, char *end, struct block_device *bdev,
			    struct printf_spec spec, const char *fmt);
#endif
char *vsprintf_c_time_and_date(char *buf, char *end, void *ptr,
				struct printf_spec spec, const char *fmt);
char *vsprintf_c_clock(char *buf, char *end, struct clk *clk,
			struct printf_spec spec, const char *fmt);
char *vsprintf_c_format_page_flags(char *buf, char *end, unsigned long flags);
char *vsprintf_c_device_node_string(char *buf, char *end, struct device_node *dn,
				    struct printf_spec spec, const char *fmt);
char *vsprintf_c_fwnode_string(char *buf, char *end, struct fwnode_handle *fwnode,
				struct printf_spec spec, const char *fmt);
char *vsprintf_c_va_format(char *buf, char *end, struct va_format *va_fmt,
			    struct printf_spec spec);

/*
 * format_decode()'s own `WARN_ONCE(1, "Please remove unsupported %%%c in
 * format string\n", *fmt.str)` -- kept here rather than reproduced in Rust
 * (kernel::kabi_warn! fires every time, not once; there's no "once+format"
 * macro in kernel::kabi to reuse) so the bug-table entry names this file,
 * not vsprintf_rs.rs. Called from vsprintf_rs_format_decode()'s own
 * fallback arm.
 */
void vsprintf_c_format_decode_invalid_warn(int c)
{
	WARN_ONCE(1, "Please remove unsupported %%%c in format string\n", c);
}
/* Disable pointer hashing if requested */
bool no_hash_pointers __ro_after_init;
EXPORT_SYMBOL_GPL(no_hash_pointers);

/*
 * Hashed pointers policy selected by "hash_pointers=..." boot param
 *
 * `auto`   - Hashed pointers enabled unless disabled by slub_debug_enabled=true
 * `always` - Hashed pointers enabled unconditionally
 * `never`  - Hashed pointers disabled unconditionally
 */
enum hash_pointers_policy {
	HASH_PTR_AUTO = 0,
	HASH_PTR_ALWAYS,
	HASH_PTR_NEVER
};
static enum hash_pointers_policy hash_pointers_mode __initdata;

noinline
static unsigned long long simple_strntoull(const char *startp, char **endp, unsigned int base, size_t max_chars)
{
	const char *cp;
	unsigned long long result = 0ULL;
	size_t prefix_chars;
	unsigned int rv;

	cp = _parse_integer_fixup_radix(startp, &base);
	prefix_chars = cp - startp;
	if (prefix_chars < max_chars) {
		rv = _parse_integer_limit(cp, base, &result, max_chars - prefix_chars);
		/* FIXME */
		cp += (rv & ~KSTRTOX_OVERFLOW);
	} else {
		/* Field too short for prefix + digit, skip over without converting */
		cp = startp + max_chars;
	}

	if (endp)
		*endp = (char *)cp;

	return result;
}

/**
 * simple_strtoull - convert a string to an unsigned long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoull instead.
 */
noinline
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoull(cp, endp, base, INT_MAX);
}
EXPORT_SYMBOL(simple_strtoull);

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoul instead.
 */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned int base)
{
	return simple_strtoull(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtoul);

unsigned long simple_strntoul(const char *cp, char **endp, unsigned int base,
			      size_t max_chars)
{
	return simple_strntoull(cp, endp, base, max_chars);
}
EXPORT_SYMBOL(simple_strntoul);

/**
 * simple_strtol - convert a string to a signed long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtol instead.
 */
long simple_strtol(const char *cp, char **endp, unsigned int base)
{
	if (*cp == '-')
		return -simple_strtoul(cp + 1, endp, base);

	return simple_strtoul(cp, endp, base);
}
EXPORT_SYMBOL(simple_strtol);

noinline
static long long simple_strntoll(const char *cp, char **endp, unsigned int base, size_t max_chars)
{
	/*
	 * simple_strntoull() safely handles receiving max_chars==0 in the
	 * case cp[0] == '-' && max_chars == 1.
	 * If max_chars == 0 we can drop through and pass it to simple_strntoull()
	 * and the content of *cp is irrelevant.
	 */
	if (*cp == '-' && max_chars > 0)
		return -simple_strntoull(cp + 1, endp, base, max_chars - 1);

	return simple_strntoull(cp, endp, base, max_chars);
}

/**
 * simple_strtoll - convert a string to a signed long long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 *
 * This function has caveats. Please use kstrtoll instead.
 */
long long simple_strtoll(const char *cp, char **endp, unsigned int base)
{
	return simple_strntoll(cp, endp, base, INT_MAX);
}
EXPORT_SYMBOL(simple_strtoll);

/* Make pointers available for printing early in the boot sequence. */
/* No longer `static` -- vsprintf_rs.rs's `extern "C" static
 * debug_boot_weak_hash: c_int` needs a linkable symbol. Deliberate
 * divergence from upstream (see this file's own module doc). */
int debug_boot_weak_hash __ro_after_init;

static int __init debug_boot_weak_hash_enable(char *str)
{
	debug_boot_weak_hash = 1;
	pr_info("debug_boot_weak_hash enabled\n");
	return 0;
}
early_param("debug_boot_weak_hash", debug_boot_weak_hash_enable);

/* Both no longer `static` -- vsprintf_rs.rs externs both directly. Same
 * deliberate divergence as debug_boot_weak_hash above. */
bool filled_random_ptr_key __read_mostly;
siphash_key_t ptr_key __read_mostly;

static int fill_ptr_key(struct notifier_block *nb, unsigned long action, void *data)
{
	get_random_bytes(&ptr_key, sizeof(ptr_key));

	/* Pairs with smp_rmb() before reading ptr_key. */
	smp_wmb();
	WRITE_ONCE(filled_random_ptr_key, true);
	return NOTIFY_DONE;
}

static int __init vsprintf_init_hashval(void)
{
	static struct notifier_block fill_ptr_key_nb = { .notifier_call = fill_ptr_key };
	execute_with_initialized_rng(&fill_ptr_key_nb);
	return 0;
}
subsys_initcall(vsprintf_init_hashval)

int kptr_restrict __read_mostly;

/*
 * `%pK` -- ported to vsprintf_rs.rs's restricted_pointer()/
 * restricted_pointer_decision() (the pure/impure split the seam's own
 * checkpoint required). What stays here: the two things that can't move
 * -- in_hardirq()/in_serving_softirq()/in_nmi() are real preempt-count
 * macros, and struct cred/current_cred()/has_capability_noaudit() are
 * real credential/LSM machinery. Both are called from Rust in the exact
 * order the original restricted_pointer()'s own comment required (IRQ
 * check first, unconditionally; the credential check ONLY when NOT in
 * IRQ context) -- Rust's own restricted_pointer() wrapper enforces that
 * ordering, not these two functions themselves.
 */
bool vsprintf_c_in_irq_context(void)
{
	return in_hardirq() || in_serving_softirq() || in_nmi();
}

/*
 * Only ever called by Rust's restricted_pointer() when it has ALREADY
 * confirmed !vsprintf_c_in_irq_context() -- current_cred() is meaningless
 * in NMI, and has_capability_noaudit() has real RCU/LSM-hook side effects
 * despite "noaudit" only suppressing the audit record. Negated from the
 * original's `!A || !B || !C` "set ptr = NULL" condition to this
 * function's own "may reveal the real pointer" sense.
 */
bool vsprintf_c_restricted_pointer_cred_ok(void)
{
	const struct cred *cred = current_cred();

	return has_capability_noaudit(current, CAP_SYSLOG) &&
	       uid_eq(cred->euid, cred->uid) &&
	       gid_eq(cred->egid, cred->gid);
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_dentry_name(char *buf, char *end, const struct dentry *d, struct printf_spec spec,
		  const char *fmt)
{
	const char *array[4], *s;
	const struct dentry *p;
	int depth;
	int i, n;

	switch (fmt[1]) {
		case '2': case '3': case '4':
			depth = fmt[1] - '0';
			break;
		default:
			depth = 1;
	}

	rcu_read_lock();
	for (i = 0; i < depth; i++, d = p) {
		if (vsprintf_rs_check_pointer(&buf, end, d, spec)) {
			rcu_read_unlock();
			return buf;
		}

		p = READ_ONCE(d->d_parent);
		array[i] = READ_ONCE(d->d_name.name);
		if (p == d) {
			if (i)
				array[i] = "";
			i++;
			break;
		}
	}
	s = array[--i];
	for (n = 0; n != spec.precision; n++, buf++) {
		char c = *s++;
		if (!c) {
			if (!i)
				break;
			c = '/';
			s = array[--i];
		}
		if (buf < end)
			*buf = c;
	}
	rcu_read_unlock();
	return vsprintf_rs_widen_string(buf, n, end, spec);
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_file_dentry_name(char *buf, char *end, const struct file *f,
			struct printf_spec spec, const char *fmt)
{
	if (vsprintf_rs_check_pointer(&buf, end, f, spec))
		return buf;

	return vsprintf_c_dentry_name(buf, end, f->f_path.dentry, spec, fmt);
}
#ifdef CONFIG_BLOCK
/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_bdev_name(char *buf, char *end, struct block_device *bdev,
		struct printf_spec spec, const char *fmt)
{
	struct gendisk *hd;

	if (vsprintf_rs_check_pointer(&buf, end, bdev, spec))
		return buf;

	hd = bdev->bd_disk;
	buf = vsprintf_rs_string(buf, end, hd->disk_name, spec);
	if (bdev_is_partition(bdev)) {
		if (isdigit(hd->disk_name[strlen(hd->disk_name)-1])) {
			if (buf < end)
				*buf = 'p';
			buf++;
		}
		buf = vsprintf_rs_number(buf, end, bdev_partno(bdev), spec);
	}
	return buf;
}
#endif
static const struct printf_spec default_str_spec = {
	.field_width = -1,
	.precision = -1,
};

static const struct printf_spec default_flag_spec = {
	.base = 16,
	.precision = -1,
	.flags = SPECIAL | SMALL,
};

static const struct printf_spec default_dec_spec = {
	.base = 10,
	.precision = -1,
};

static const struct printf_spec default_dec02_spec = {
	.base = 10,
	.field_width = 2,
	.precision = -1,
	.flags = ZEROPAD,
};

static const struct printf_spec default_dec04_spec = {
	.base = 10,
	.field_width = 4,
	.precision = -1,
	.flags = ZEROPAD,
};
__diag_push();
__diag_ignore(GCC, all, "-Wsuggest-attribute=format",
	      "Not a valid __printf() conversion candidate.");
/* `%pV` -- permanently C (not just deferred): `va_copy()`/`va_end()` on
 * the `va_list` inside `struct va_format` is the same `va_list` machinery
 * this file's own `vsnprintf()` needs, see the module doc. No longer
 * `static` -- called from Rust. */
char *vsprintf_c_va_format(char *buf, char *end, struct va_format *va_fmt,
		       struct printf_spec spec)
{
	va_list va;

	if (vsprintf_rs_check_pointer(&buf, end, va_fmt, spec))
		return buf;

	va_copy(va, *va_fmt->va);
	buf += vsnprintf(buf, end > buf ? end - buf : 0, va_fmt->fmt, va);
	va_end(va);

	return buf;
}
__diag_pop();
static noinline_for_stack
char *date_str(char *buf, char *end, const struct rtc_time *tm, bool r)
{
	int year = tm->tm_year + (r ? 0 : 1900);
	int mon = tm->tm_mon + (r ? 0 : 1);

	buf = vsprintf_rs_number(buf, end, year, default_dec04_spec);
	if (buf < end)
		*buf = '-';
	buf++;

	buf = vsprintf_rs_number(buf, end, mon, default_dec02_spec);
	if (buf < end)
		*buf = '-';
	buf++;

	return vsprintf_rs_number(buf, end, tm->tm_mday, default_dec02_spec);
}

static noinline_for_stack
char *time_str(char *buf, char *end, const struct rtc_time *tm, bool r)
{
	buf = vsprintf_rs_number(buf, end, tm->tm_hour, default_dec02_spec);
	if (buf < end)
		*buf = ':';
	buf++;

	buf = vsprintf_rs_number(buf, end, tm->tm_min, default_dec02_spec);
	if (buf < end)
		*buf = ':';
	buf++;

	return vsprintf_rs_number(buf, end, tm->tm_sec, default_dec02_spec);
}

static noinline_for_stack
char *rtc_str(char *buf, char *end, const struct rtc_time *tm,
	      struct printf_spec spec, const char *fmt)
{
	bool have_t = true, have_d = true;
	bool raw = false, iso8601_separator = true;
	bool found = true;
	int count = 2;

	switch (fmt[count]) {
	case 'd':
		have_t = false;
		count++;
		break;
	case 't':
		have_d = false;
		count++;
		break;
	}

	do {
		switch (fmt[count++]) {
		case 'r':
			raw = true;
			break;
		case 's':
			iso8601_separator = false;
			break;
		default:
			found = false;
			break;
		}
	} while (found);

	if (have_d)
		buf = date_str(buf, end, tm, raw);
	if (have_d && have_t) {
		if (buf < end)
			*buf = iso8601_separator ? 'T' : ' ';
		buf++;
	}
	if (have_t)
		buf = time_str(buf, end, tm, raw);

	return buf;
}

static noinline_for_stack
char *time64_str(char *buf, char *end, const time64_t time,
		 struct printf_spec spec, const char *fmt)
{
	struct rtc_time rtc_time;
	struct tm tm;

	time64_to_tm(time, 0, &tm);

	rtc_time.tm_sec = tm.tm_sec;
	rtc_time.tm_min = tm.tm_min;
	rtc_time.tm_hour = tm.tm_hour;
	rtc_time.tm_mday = tm.tm_mday;
	rtc_time.tm_mon = tm.tm_mon;
	rtc_time.tm_year = tm.tm_year;
	rtc_time.tm_wday = tm.tm_wday;
	rtc_time.tm_yday = tm.tm_yday;

	rtc_time.tm_isdst = 0;

	return rtc_str(buf, end, &rtc_time, spec, fmt);
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_time_and_date(char *buf, char *end, void *ptr, struct printf_spec spec,
		    const char *fmt)
{
	if (vsprintf_rs_check_pointer(&buf, end, ptr, spec))
		return buf;

	switch (fmt[1]) {
	case 'R':
		return rtc_str(buf, end, (const struct rtc_time *)ptr, spec, fmt);
	case 'T':
		return time64_str(buf, end, *(const time64_t *)ptr, spec, fmt);
	default:
		return vsprintf_rs_error_string(buf, end, "(%pt?)", spec);
	}
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_clock(char *buf, char *end, struct clk *clk, struct printf_spec spec,
	    const char *fmt)
{
	if (!IS_ENABLED(CONFIG_HAVE_CLK))
		return vsprintf_rs_error_string(buf, end, "(%pC?)", spec);

	if (vsprintf_rs_check_pointer(&buf, end, clk, spec))
		return buf;

#ifdef CONFIG_COMMON_CLK
	return vsprintf_rs_string(buf, end, __clk_get_name(clk), spec);
#else
	return vsprintf_rs_ptr_to_id(buf, end, clk, spec);
#endif
}
struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

static const struct page_flags_fields pff[] = {
	{SECTIONS_WIDTH, SECTIONS_PGSHIFT, SECTIONS_MASK,
	 &default_dec_spec, "section"},
	{NODES_WIDTH, NODES_PGSHIFT, NODES_MASK,
	 &default_dec_spec, "node"},
	{ZONES_WIDTH, ZONES_PGSHIFT, ZONES_MASK,
	 &default_dec_spec, "zone"},
	{LAST_CPUPID_WIDTH, LAST_CPUPID_PGSHIFT, LAST_CPUPID_MASK,
	 &default_flag_spec, "lastcpupid"},
	{KASAN_TAG_WIDTH, KASAN_TAG_PGSHIFT, KASAN_TAG_MASK,
	 &default_flag_spec, "kasantag"},
};

/* `%pGp` -- deferred, see this file's own module doc. No longer `static`
 * (upstream: `static char *format_page_flags(...)`) -- vsprintf_rs.rs's
 * `flags_string()` calls this directly for its own `'p'` case. */
char *vsprintf_c_format_page_flags(char *buf, char *end, unsigned long flags)
{
	unsigned long main_flags = flags & PAGEFLAGS_MASK;
	bool append = false;
	int i;

	buf = vsprintf_rs_number(buf, end, flags, default_flag_spec);
	if (buf < end)
		*buf = '(';
	buf++;

	/* Page flags from the main area. */
	if (main_flags) {
		buf = vsprintf_rs_format_flags(buf, end, main_flags, pageflag_names);
		append = true;
	}

	/* Page flags from the fields area */
	for (i = 0; i < ARRAY_SIZE(pff); i++) {
		/* Skip undefined fields. */
		if (!pff[i].width)
			continue;

		/* Format: Flag Name + '=' (equals sign) + Number + '|' (separator) */
		if (append) {
			if (buf < end)
				*buf = '|';
			buf++;
		}

		buf = vsprintf_rs_string(buf, end, pff[i].name, default_str_spec);
		if (buf < end)
			*buf = '=';
		buf++;
		buf = vsprintf_rs_number(buf, end, (flags >> pff[i].shift) & pff[i].mask,
			     *pff[i].spec);

		append = true;
	}
	if (buf < end)
		*buf = ')';
	buf++;

	return buf;
}
static noinline_for_stack
char *fwnode_full_name_string(struct fwnode_handle *fwnode, char *buf,
			      char *end)
{
	int depth;

	/* Loop starting from the root node to the current node. */
	for (depth = fwnode_count_parents(fwnode); depth >= 0; depth--) {
		/*
		 * Only get a reference for other nodes (i.e. parent nodes).
		 * fwnode refcount may be 0 here.
		 */
		struct fwnode_handle *__fwnode = depth ?
			fwnode_get_nth_parent(fwnode, depth) : fwnode;

		buf = vsprintf_rs_string(buf, end, fwnode_get_name_prefix(__fwnode),
			     default_str_spec);
		buf = vsprintf_rs_string(buf, end, fwnode_get_name(__fwnode),
			     default_str_spec);

		if (depth)
			fwnode_handle_put(__fwnode);
	}

	return buf;
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_device_node_string(char *buf, char *end, struct device_node *dn,
			 struct printf_spec spec, const char *fmt)
{
	char tbuf[sizeof("xxxx") + 1];
	const char *p;
	int ret;
	char *buf_start = buf;
	struct property *prop;
	bool has_mult, pass;

	struct printf_spec str_spec = spec;
	str_spec.field_width = -1;

	if (fmt[0] != 'F')
		return vsprintf_rs_error_string(buf, end, "(%pO?)", spec);

	if (!IS_ENABLED(CONFIG_OF))
		return vsprintf_rs_error_string(buf, end, "(%pOF?)", spec);

	if (vsprintf_rs_check_pointer(&buf, end, dn, spec))
		return buf;

	/* simple case without anything any more format specifiers */
	fmt++;
	if (fmt[0] == '\0' || strcspn(fmt,"fnpPFcC") > 0)
		fmt = "f";

	for (pass = false; strspn(fmt,"fnpPFcC"); fmt++, pass = true) {
		int precision;
		if (pass) {
			if (buf < end)
				*buf = ':';
			buf++;
		}

		switch (*fmt) {
		case 'f':	/* full_name */
			buf = fwnode_full_name_string(of_fwnode_handle(dn), buf,
						      end);
			break;
		case 'n':	/* name */
			p = fwnode_get_name(of_fwnode_handle(dn));
			precision = str_spec.precision;
			str_spec.precision = strchrnul(p, '@') - p;
			buf = vsprintf_rs_string(buf, end, p, str_spec);
			str_spec.precision = precision;
			break;
		case 'p':	/* phandle */
			buf = vsprintf_rs_number(buf, end, (unsigned int)dn->phandle, default_dec_spec);
			break;
		case 'P':	/* path-spec */
			p = fwnode_get_name(of_fwnode_handle(dn));
			if (!p[1])
				p = "/";
			buf = vsprintf_rs_string(buf, end, p, str_spec);
			break;
		case 'F':	/* flags */
			tbuf[0] = of_node_check_flag(dn, OF_DYNAMIC) ? 'D' : '-';
			tbuf[1] = of_node_check_flag(dn, OF_DETACHED) ? 'd' : '-';
			tbuf[2] = of_node_check_flag(dn, OF_POPULATED) ? 'P' : '-';
			tbuf[3] = of_node_check_flag(dn, OF_POPULATED_BUS) ? 'B' : '-';
			tbuf[4] = 0;
			buf = vsprintf_rs_string_nocheck(buf, end, tbuf, str_spec);
			break;
		case 'c':	/* major compatible string */
			ret = of_property_read_string(dn, "compatible", &p);
			if (!ret)
				buf = vsprintf_rs_string(buf, end, p, str_spec);
			break;
		case 'C':	/* full compatible string */
			has_mult = false;
			of_property_for_each_string(dn, "compatible", prop, p) {
				if (has_mult)
					buf = vsprintf_rs_string_nocheck(buf, end, ",", str_spec);
				buf = vsprintf_rs_string_nocheck(buf, end, "\"", str_spec);
				buf = vsprintf_rs_string(buf, end, p, str_spec);
				buf = vsprintf_rs_string_nocheck(buf, end, "\"", str_spec);

				has_mult = true;
			}
			break;
		default:
			break;
		}
	}

	return vsprintf_rs_widen_string(buf, buf - buf_start, end, spec);
}

/* No longer `static` -- called from Rust. */
noinline_for_stack
char *vsprintf_c_fwnode_string(char *buf, char *end, struct fwnode_handle *fwnode,
		    struct printf_spec spec, const char *fmt)
{
	struct printf_spec str_spec = spec;
	char *buf_start = buf;

	str_spec.field_width = -1;

	if (*fmt != 'w')
		return vsprintf_rs_error_string(buf, end, "(%pf?)", spec);

	if (vsprintf_rs_check_pointer(&buf, end, fwnode, spec))
		return buf;

	fmt++;

	switch (*fmt) {
	case 'P':	/* name */
		buf = vsprintf_rs_string(buf, end, fwnode_get_name(fwnode), str_spec);
		break;
	case 'f':	/* full_name */
	default:
		buf = fwnode_full_name_string(fwnode, buf, end);
		break;
	}

	return vsprintf_rs_widen_string(buf, buf - buf_start, end, spec);
}
void __init hash_pointers_finalize(bool slub_debug)
{
	switch (hash_pointers_mode) {
	case HASH_PTR_ALWAYS:
		no_hash_pointers = false;
		break;
	case HASH_PTR_NEVER:
		no_hash_pointers = true;
		break;
	case HASH_PTR_AUTO:
	default:
		no_hash_pointers = slub_debug;
		break;
	}

	if (!no_hash_pointers)
		return;

	pr_warn("**********************************************************\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** This system shows unhashed kernel memory addresses   **\n");
	pr_warn("** via the console, logs, and other interfaces. This    **\n");
	pr_warn("** might reduce the security of your system.            **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** If you see this message and you are not debugging    **\n");
	pr_warn("** the kernel, report this immediately to your system   **\n");
	pr_warn("** administrator!                                       **\n");
	pr_warn("**                                                      **\n");
	pr_warn("** Use hash_pointers=always to force this mode off      **\n");
	pr_warn("**                                                      **\n");
	pr_warn("**   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **\n");
	pr_warn("**********************************************************\n");
}

static int __init hash_pointers_mode_parse(char *str)
{
	if (!str) {
		pr_warn("Hash pointers mode empty; falling back to auto.\n");
		hash_pointers_mode = HASH_PTR_AUTO;
	} else if (strncmp(str, "auto", 4) == 0)   {
		pr_info("Hash pointers mode set to auto.\n");
		hash_pointers_mode = HASH_PTR_AUTO;
	} else if (strncmp(str, "never", 5) == 0) {
		pr_info("Hash pointers mode set to never.\n");
		hash_pointers_mode = HASH_PTR_NEVER;
	} else if (strncmp(str, "always", 6) == 0) {
		pr_info("Hash pointers mode set to always.\n");
		hash_pointers_mode = HASH_PTR_ALWAYS;
	} else {
		pr_warn("Unknown hash_pointers mode '%s' specified; assuming auto.\n", str);
		hash_pointers_mode = HASH_PTR_AUTO;
	}

	return 0;
}
early_param("hash_pointers", hash_pointers_mode_parse);

static int __init no_hash_pointers_enable(char *str)
{
	return hash_pointers_mode_parse("never");
}
early_param("no_hash_pointers", no_hash_pointers_enable);

int vsnprintf(char *buf, size_t size, const char *fmt_str, va_list args)
{
	char *str, *end;
	struct printf_spec spec = {0};
	struct fmt fmt = {
		.str = fmt_str,
		.state = FORMAT_STATE_NONE,
	};

	/* Reject out-of-range values early.  Large positive sizes are
	   used for unknown buffer sizes. */
	if (WARN_ON_ONCE(size > INT_MAX))
		return 0;

	str = buf;
	end = buf + size;

	/* Make sure end is always >= buf */
	if (end < buf) {
		end = ((void *)-1);
		size = end - buf;
	}

	while (*fmt.str) {
		const char *old_fmt = fmt.str;

		fmt = vsprintf_rs_format_decode(fmt, &spec);

		switch (fmt.state) {
		case FORMAT_STATE_NONE: {
			int read = fmt.str - old_fmt;
			if (str < end) {
				int copy = read;
				if (copy > end - str)
					copy = end - str;
				memcpy(str, old_fmt, copy);
			}
			str += read;
			continue;
		}

		case FORMAT_STATE_NUM: {
			unsigned long long num;
			if (fmt.size <= sizeof(int))
				num = vsprintf_rs_convert_num_spec(va_arg(args, int), fmt.size, spec);
			else
				num = va_arg(args, long long);
			str = vsprintf_rs_number(str, end, num, spec);
			continue;
		}

		case FORMAT_STATE_WIDTH:
			vsprintf_rs_set_field_width(&spec, va_arg(args, int));
			continue;

		case FORMAT_STATE_PRECISION:
			vsprintf_rs_set_precision(&spec, va_arg(args, int));
			continue;

		case FORMAT_STATE_CHAR: {
			char c;

			if (!(spec.flags & LEFT)) {
				while (--spec.field_width > 0) {
					if (str < end)
						*str = ' ';
					++str;

				}
			}
			c = (unsigned char) va_arg(args, int);
			if (str < end)
				*str = c;
			++str;
			while (--spec.field_width > 0) {
				if (str < end)
					*str = ' ';
				++str;
			}
			continue;
		}

		case FORMAT_STATE_STR:
			str = vsprintf_rs_string(str, end, va_arg(args, char *), spec);
			continue;

		case FORMAT_STATE_PTR:
			str = vsprintf_rs_pointer(fmt.str, str, end, va_arg(args, void *),
				      spec);
			while (isalnum(*fmt.str))
				fmt.str++;
			continue;

		case FORMAT_STATE_PERCENT_CHAR:
			if (str < end)
				*str = '%';
			++str;
			continue;

		default:
			/*
			 * Presumably the arguments passed gcc's type
			 * checking, but there is no safe or sane way
			 * for us to continue parsing the format and
			 * fetching from the va_list; the remaining
			 * specifiers and arguments would be out of
			 * sync.
			 */
			goto out;
		}
	}

out:
	if (size > 0) {
		if (str < end)
			*str = '\0';
		else
			end[-1] = '\0';
	}

	/* the trailing null byte doesn't count towards the total */
	return str-buf;

}
EXPORT_SYMBOL(vsnprintf);
/**
 * vscnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The return value is the number of characters which have been written into
 * the @buf not including the trailing '\0'. If @size is == 0 the function
 * returns 0.
 *
 * If you're not already dealing with a va_list consider using scnprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
{
	int i;

	if (unlikely(!size))
		return 0;

	i = vsnprintf(buf, size, fmt, args);

	if (likely(i < size))
		return i;

	return size - 1;
}
EXPORT_SYMBOL(vscnprintf);

/**
 * snprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters which would be
 * generated for the given input, excluding the trailing null,
 * as per ISO C99.  If the return is greater than or equal to
 * @size, the resulting string is truncated.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(snprintf);

/**
 * scnprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @size: The size of the buffer, including the trailing null space
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The return value is the number of characters written into @buf not including
 * the trailing '\0'. If @size is == 0 the function returns 0.
 */

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vscnprintf(buf, size, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(scnprintf);

/**
 * vsprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @args: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use vsnprintf() or vscnprintf() in order to avoid
 * buffer overflows.
 *
 * If you're not already dealing with a va_list consider using sprintf().
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int vsprintf(char *buf, const char *fmt, va_list args)
{
	return vsnprintf(buf, INT_MAX, fmt, args);
}
EXPORT_SYMBOL(vsprintf);

/**
 * sprintf - Format a string and place it in a buffer
 * @buf: The buffer to place the result into
 * @fmt: The format string to use
 * @...: Arguments for the format string
 *
 * The function returns the number of characters written
 * into @buf. Use snprintf() or scnprintf() in order to avoid
 * buffer overflows.
 *
 * See the vsnprintf() documentation for format string extensions over C99.
 */
int sprintf(char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsnprintf(buf, INT_MAX, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sprintf);
#ifdef CONFIG_BINARY_PRINTF
/*
 * bprintf service:
 * vbin_printf() - VA arguments to binary data
 * bstr_printf() - Binary data to text string
 */

/**
 * vbin_printf - Parse a format string and place args' binary value in a buffer
 * @bin_buf: The buffer to place args' binary value
 * @size: The size of the buffer(by words(32bits), not characters)
 * @fmt_str: The format string to use
 * @args: Arguments for the format string
 *
 * The format follows C99 vsnprintf, except %n is ignored, and its argument
 * is skipped.
 *
 * The return value is the number of words(32bits) which would be generated for
 * the given input.
 *
 * NOTE:
 * If the return value is greater than @size, the resulting bin_buf is NOT
 * valid for bstr_printf().
 */
int vbin_printf(u32 *bin_buf, size_t size, const char *fmt_str, va_list args)
{
	struct fmt fmt = {
		.str = fmt_str,
		.state = FORMAT_STATE_NONE,
	};
	struct printf_spec spec = {0};
	char *str, *end;
	int width;

	str = (char *)bin_buf;
	end = (char *)(bin_buf + size);

#define save_arg(type)							\
({									\
	unsigned long long value;					\
	if (sizeof(type) == 8) {					\
		unsigned long long val8;				\
		str = PTR_ALIGN(str, sizeof(u32));			\
		val8 = va_arg(args, unsigned long long);		\
		if (str + sizeof(type) <= end) {			\
			*(u32 *)str = *(u32 *)&val8;			\
			*(u32 *)(str + 4) = *((u32 *)&val8 + 1);	\
		}							\
		value = val8;						\
	} else {							\
		unsigned int val4;					\
		str = PTR_ALIGN(str, sizeof(type));			\
		val4 = va_arg(args, int);				\
		if (str + sizeof(type) <= end)				\
			*(typeof(type) *)str = (type)(long)val4;	\
		value = (unsigned long long)val4;			\
	}								\
	str += sizeof(type);						\
	value;								\
})

	while (*fmt.str) {
		fmt = vsprintf_rs_format_decode(fmt, &spec);

		switch (fmt.state) {
		case FORMAT_STATE_NONE:
		case FORMAT_STATE_PERCENT_CHAR:
			break;
		case FORMAT_STATE_INVALID:
			goto out;

		case FORMAT_STATE_WIDTH:
		case FORMAT_STATE_PRECISION:
			width = (int)save_arg(int);
			/* Pointers may require the width */
			if (*fmt.str == 'p')
				vsprintf_rs_set_field_width(&spec, width);
			break;

		case FORMAT_STATE_CHAR:
			save_arg(char);
			break;

		case FORMAT_STATE_STR: {
			const char *save_str = va_arg(args, char *);
			const char *err_msg;
			size_t len;

			err_msg = vsprintf_rs_check_pointer_msg(save_str);
			if (err_msg)
				save_str = err_msg;

			len = strlen(save_str) + 1;
			if (str + len < end)
				memcpy(str, save_str, len);
			str += len;
			break;
		}

		case FORMAT_STATE_PTR:
			/* Dereferenced pointers must be done now */
			switch (*fmt.str) {
			/* Dereference of functions is still OK */
			case 'S':
			case 's':
			case 'x':
			case 'K':
			case 'e':
				save_arg(void *);
				break;
			default:
				if (!isalnum(*fmt.str)) {
					save_arg(void *);
					break;
				}
				str = vsprintf_rs_pointer(fmt.str, str, end, va_arg(args, void *),
					      spec);
				if (str + 1 < end)
					*str++ = '\0';
				else
					end[-1] = '\0'; /* Must be nul terminated */
			}
			/* skip all alphanumeric pointer suffixes */
			while (isalnum(*fmt.str))
				fmt.str++;
			break;

		case FORMAT_STATE_NUM:
			if (fmt.size > sizeof(int)) {
				save_arg(long long);
			} else {
				save_arg(int);
			}
		}
	}

out:
	return (u32 *)(PTR_ALIGN(str, sizeof(u32))) - bin_buf;
#undef save_arg
}
EXPORT_SYMBOL_GPL(vbin_printf);
#endif /* CONFIG_BINARY_PRINTF */

/*
 * vsscanf() -- ported to Rust, lib/vsprintf_scan_rs.rs. See that file's
 * module doc for the full design (why this can't split the way
 * format_decode()/get_arg did, and the va_arg-consumption-order
 * subtlety for '%['). What stays here: the va_list-typed entry point
 * itself (same reason vsnprintf()/vbin_printf() do), the va_arg
 * extraction switch for numeric qualifiers (unchanged from upstream),
 * and the simple_strntoll()/simple_strntoull() calls (an independent,
 * low-risk follow-up if ever wanted, not required for this split).
 *
 * skip_atoi()'s own vsscanf-local copy is gone: the format-string walk
 * that used it (field-width parsing) moved to Rust entirely.
 */

/**
 * vsscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	format of buffer
 * @args:	arguments
 */
int vsscanf(const char *buf, const char *fmt, va_list args)
{
	const char *str = buf;
	char *next;
	int num = 0;
	union {
		long long s;
		unsigned long long u;
	} val;

	while (*fmt) {
		struct scan_spec spec = vsprintf_scan_rs_next(&fmt, &str, buf);

		switch (spec.kind) {
		case SCAN_DONE:
			goto out;
		case SCAN_CONTINUE:
			continue;
		case SCAN_NEED_N:
			/* return number of characters read so far */
			*va_arg(args, int *) = str - buf;
			continue;
		case SCAN_NEED_C: {
			char *s = (char *)va_arg(args, char *);

			vsprintf_scan_rs_consume_c(&str, spec.field_width, s);
			num++;
		}
		continue;
		case SCAN_NEED_S: {
			char *s = (char *)va_arg(args, char *);

			vsprintf_scan_rs_consume_s(&str, spec.field_width, s);
			num++;
		}
		continue;
		case SCAN_NEED_BRACKET: {
			/*
			 * va_arg is consumed unconditionally here, matching
			 * upstream, even on the `stop` (no match) path --
			 * see vsprintf_scan_rs.rs's module doc.
			 */
			char *s = (char *)va_arg(args, char *);

			if (spec.stop)
				goto out;
			vsprintf_scan_rs_consume_bracket(&str, spec.field_width, spec.set, s);
			num++;
		}
		continue;
		case SCAN_NEED_NUMERIC:
			if (spec.is_sign)
				val.s = simple_strntoll(str, &next, spec.base,
							spec.field_width >= 0 ? spec.field_width : INT_MAX);
			else
				val.u = simple_strntoull(str, &next, spec.base,
							 spec.field_width >= 0 ? spec.field_width : INT_MAX);

			switch (spec.qualifier) {
			case 'H':	/* that's 'hh' in format */
				if (spec.is_sign)
					*va_arg(args, signed char *) = val.s;
				else
					*va_arg(args, unsigned char *) = val.u;
				break;
			case 'h':
				if (spec.is_sign)
					*va_arg(args, short *) = val.s;
				else
					*va_arg(args, unsigned short *) = val.u;
				break;
			case 'l':
				if (spec.is_sign)
					*va_arg(args, long *) = val.s;
				else
					*va_arg(args, unsigned long *) = val.u;
				break;
			case 'L':
				if (spec.is_sign)
					*va_arg(args, long long *) = val.s;
				else
					*va_arg(args, unsigned long long *) = val.u;
				break;
			case 'z':
				*va_arg(args, size_t *) = val.u;
				break;
			default:
				if (spec.is_sign)
					*va_arg(args, int *) = val.s;
				else
					*va_arg(args, unsigned int *) = val.u;
				break;
			}
			num++;

			if (!next)
				goto out;
			str = next;
			continue;
		}
	}

out:
	return num;
}
EXPORT_SYMBOL(vsscanf);

/**
 * sscanf - Unformat a buffer into a list of arguments
 * @buf:	input buffer
 * @fmt:	formatting of buffer
 * @...:	resulting arguments
 */
int sscanf(const char *buf, const char *fmt, ...)
{
	va_list args;
	int i;

	va_start(args, fmt);
	i = vsscanf(buf, fmt, args);
	va_end(args);

	return i;
}
EXPORT_SYMBOL(sscanf);
