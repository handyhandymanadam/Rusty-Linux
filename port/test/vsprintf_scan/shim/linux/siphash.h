/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_SIPHASH_H
#define _SHIM_VSPRINTF_LINUX_SIPHASH_H
#include <linux/types.h>

/* Real layout, include/linux/siphash.h. */
typedef struct {
	u64 key[2];
} siphash_key_t;

/* Stubbed (deterministic, NOT the real siphash algorithm) in stubs.c and
 * shared by both the REF and RS arms via the same extern names -- what
 * this harness tests is ptr_to_id()'s own hash-then-format logic, not
 * siphash's correctness (verified separately, its own port/test/siphash/).
 */
u64 siphash_1u64(u64 first, const siphash_key_t *key);
u64 siphash_1u32(u32 first, const siphash_key_t *key);

#endif
