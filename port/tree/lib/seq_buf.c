// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * Everything else in the pristine file moved to lib/seq_buf_rs.rs:
 * seq_buf_print_seq(), seq_buf_do_printk(), seq_buf_puts(), seq_buf_putc(),
 * seq_buf_putmem(), seq_buf_putmem_hex(), seq_buf_path(), seq_buf_to_user(),
 * seq_buf_hex_dump(), seq_buf_bprintf(). Two things stay:
 *
 *   - seq_buf_printf() is EXPORT_SYMBOL_GPL and is itself a variadic
 *     (`...`) function definition -- stable Rust can DECLARE and CALL a
 *     variadic C function, but cannot DEFINE one. No kabi pin applies:
 *     the export never leaves C.
 *   - seq_buf_vprintf() consumes the va_list a variadic caller built and
 *     forwards it to vsnprintf(). It is not EXPORT_SYMBOL'd (nothing
 *     outside lib/ calls it directly), but it stays beside
 *     seq_buf_printf() for the same reason: va_list is a C-only capability
 *     stable Rust has no representation for. Kept together rather than
 *     split further -- there is no useful boundary between "hold the
 *     va_list" and "the one caller that produces it".
 *
 * rust_seq_buf_copy_to_user() is the same shape as lib/strncpy_from_user.c's
 * retained thunks: copy_to_user() is a `static __always_inline` wrapper
 * (check_copy_size(), then access_ok()/instrument_copy_to_user()/
 * raw_copy_to_user() inline, or the real out-of-line _copy_to_user() --
 * see include/linux/uaccess.h), not a linkable symbol, so Rust cannot call
 * it directly. This one-line thunk is the whole of it -- no STAC/CLAC
 * bracket to keep at a particular granularity here, since copy_to_user()
 * itself already contains its own.
 */

#include <linux/export.h>
#include <linux/printk.h>
#include <linux/seq_buf.h>
#include <linux/sprintf.h>
#include <linux/types.h>
#include <linux/uaccess.h>

/* Forward-declared for the same reason as lib/strncpy_from_user.c's
 * rust_strncpy_uaccess_get_long(): config-full's -Wmissing-prototypes is
 * fatal (-Werror) and this symbol's only caller is Rust, via FFI.
 */
unsigned long rust_seq_buf_copy_to_user(char __user *to, const void *from, unsigned long n);

int seq_buf_vprintf(struct seq_buf *s, const char *fmt, va_list args)
{
	int len;

	WARN_ON(s->size == 0);

	if (s->len < s->size) {
		len = vsnprintf(s->buffer + s->len, s->size - s->len, fmt, args);
		if (s->len + len < s->size) {
			s->len += len;
			return 0;
		}
	}
	seq_buf_set_overflow(s);
	return -1;
}

int seq_buf_printf(struct seq_buf *s, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = seq_buf_vprintf(s, fmt, ap);
	va_end(ap);

	return ret;
}
EXPORT_SYMBOL_GPL(seq_buf_printf);

unsigned long rust_seq_buf_copy_to_user(char __user *to, const void *from, unsigned long n)
{
	return copy_to_user(to, from, n);
}
