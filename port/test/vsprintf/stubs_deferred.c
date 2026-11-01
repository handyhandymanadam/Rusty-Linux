/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The 8 deferred %p handlers plus %pA/%pV, plus %pK's two impure-state C
 * helpers -- used ONLY by run.sh's Island A (pointer()-direct) and
 * run_binbuf.sh's Island B, neither of which link port/tree/lib/vsprintf.c
 * (the real definitions of these). run_vsnprintf.sh's Island C links the
 * real vsprintf.c instead, so it must NOT also link this file (duplicate
 * symbols).
 *
 * vsprintf_c_in_irq_context/vsprintf_c_restricted_pointer_cred_ok are
 * restricted_pointer()'s impure wrapper's two calls into real kernel state
 * (IRQ context, current_cred()/has_capability_noaudit()) -- genuinely not
 * constructible in userspace, which is exactly why the PURE decision logic
 * (restricted_pointer_decision) is tested separately via
 * vsprintf_rs_restricted_pointer_decision instead. Neither island's corpus
 * ever constructs a d/D/g/t/C/K/O/f/V/A format spec, so these stubs exist
 * only to satisfy the linker; each aborts if actually called, so a corpus
 * bug that accidentally reaches one fails loudly rather than silently
 * comparing garbage.
 */
#include <stdio.h>
#include <stdlib.h>
#include <linux/siphash.h>

/*
 * RS-facing globals -- vsprintf_rs.o's own `extern "C" static` declarations
 * for these four (no_hash_pointers/filled_random_ptr_key/ptr_key/
 * debug_boot_weak_hash) need exactly one real definition somewhere in the
 * link. Island A (run.sh) provides it here since it doesn't link
 * port/tree/lib/vsprintf.c at all; Island C (run_vsnprintf.sh) links that
 * file instead, which is the REAL, production definition of all four --
 * defining them a second time here would collide. `filled_random_ptr_key
 * = true` and a fixed `ptr_key` put ptr_to_id() on its real
 * hash-computing path (not the "-EBUSY, key not filled yet" branch)
 * deterministically, every run.
 */
_Bool no_hash_pointers;
int kptr_restrict;
_Bool filled_random_ptr_key = 1;
siphash_key_t ptr_key = { .key = { 0x0123456789abcdefULL, 0xfedcba9876543210ULL } };
int debug_boot_weak_hash;

/* format_decode()'s own WARN_ONCE, see vsprintf_rs.rs's own comment on
 * vsprintf_c_format_decode_invalid_warn -- never reached by this harness's
 * corpus (no case constructs a genuinely unsupported format character).
 * Island C links port/tree/lib/vsprintf.c's own real definition instead. */
void vsprintf_c_format_decode_invalid_warn(int c)
{
	fprintf(stderr, "unexpected: vsprintf_c_format_decode_invalid_warn(%d)\n", c);
}

struct printf_spec_stub {
	unsigned char flags, base;
	short precision;
	int field_width;
} __attribute__((packed));

static char *unreached(const char *who)
{
	fprintf(stderr, "test bug: reached deferred handler %s (out of this harness's scope)\n", who);
	abort();
}
char *vsprintf_c_dentry_name(char *buf, char *end, const void *d, struct printf_spec_stub spec, const char *fmt) { return unreached("dentry_name"); }
char *vsprintf_c_file_dentry_name(char *buf, char *end, const void *f, struct printf_spec_stub spec, const char *fmt) { return unreached("file_dentry_name"); }
char *vsprintf_c_bdev_name(char *buf, char *end, const void *bdev, struct printf_spec_stub spec, const char *fmt) { return unreached("bdev_name"); }
char *vsprintf_c_device_node_string(char *buf, char *end, const void *dn, struct printf_spec_stub spec, const char *fmt) { return unreached("device_node_string"); }
char *vsprintf_c_fwnode_string(char *buf, char *end, const void *fwnode, struct printf_spec_stub spec, const char *fmt) { return unreached("fwnode_string"); }
char *vsprintf_c_time_and_date(char *buf, char *end, const void *ptr, struct printf_spec_stub spec, const char *fmt) { return unreached("time_and_date"); }
char *vsprintf_c_clock(char *buf, char *end, const void *clk, struct printf_spec_stub spec, const char *fmt) { return unreached("clock"); }
char *vsprintf_c_format_page_flags(char *buf, char *end, unsigned long flags) { return unreached("format_page_flags"); }
char *vsprintf_c_va_format(char *buf, char *end, const void *ptr, struct printf_spec_stub spec) { return unreached("va_format"); }
_Bool vsprintf_c_in_irq_context(void) { unreached("in_irq_context"); return 0; }
_Bool vsprintf_c_restricted_pointer_cred_ok(void) { unreached("restricted_pointer_cred_ok"); return 0; }
