#pragma once
/* Userspace has no real user/kernel boundary and no page faults to recover
 * from -- so this shim SIMULATES one, the same way for every arm that
 * includes it: g_fault_at (set by drv.c) is the first address treated as
 * unmapped, or NULL for "nothing faults". unsafe_get_user() checks it before
 * every read.
 *
 * This ONE macro definition serves all four C translation units the harness
 * links: port/pristine/lib/{strnlen_user,strncpy_from_user}.c (the oracle,
 * whose OWN unsafe_get_user() calls this) AND port/tree/lib/{same} (the
 * real, shipped retained-C thunks, whose rust_uaccess_get_long/byte()
 * helpers ALSO call unsafe_get_user() -- the exact call this shim is
 * standing in for in the real kernel). Driving both arms' fault behaviour
 * from one knob is what makes the comparison meaningful.
 */
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

extern const unsigned char *g_fault_at;

#define unsafe_get_user(x, ptr, err_label)                              \
	do {                                                              \
		const unsigned char *__p = (const unsigned char *)(ptr); \
		if (g_fault_at && __p + sizeof(x) > g_fault_at)          \
			goto err_label;                                  \
		memcpy(&(x), __p, sizeof(x));                            \
	} while (0)

/* CONFIG_X86_MASKED_USER_ACCESS is unset in both real project configs
 * (confirmed by grep, md5-porter 2026-09-05), so can_do_masked_user_access()
 * is dead code there and dead here too -- reproduced only so the pristine
 * C's branch still compiles, never taken. */
#define can_do_masked_user_access() 0
#define masked_user_access_begin(src) (src)

static inline int user_read_access_begin(const void *ptr, unsigned long len)
{
	(void)ptr;
	(void)len;
	return 1;
}
#define user_access_begin user_read_access_begin
#define user_read_access_end() do { } while (0)
#define user_access_end() do { } while (0)

static inline void might_fault(void) { }

/* No real address-space ceiling in userspace: a heap pointer's value is
 * always far below any TASK_SIZE_MAX-shaped constant, so max_addr - src_addr
 * never clips below count. That clamp is unchanged C on both arms anyway --
 * not what this harness exists to test. */
#define TASK_SIZE_MAX (~0UL)
#define untagged_addr(p) ((unsigned long)(p))
