/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_UNALIGNED_H
#define _SHIM_LINUX_UNALIGNED_H
#include <linux/types.h>
#include <string.h>
/* THE BYTESWAP IS NOT OPTIONAL, and until 2026-09-04 it was missing.
 *
 * These four were a bare memcpy -- native order -- with a comment saying
 * "identity; le on x86". That is right on x86 and WRONG everywhere else, and
 * because it is the ORACLE that reads memory this way, the error does not
 * cancel: lib/xxhash.c reaches its byte order ONLY through these functions
 * (XXH_CPU_LITTLE_ENDIAN is defined at xxhash.c:55-59 and then never used),
 * so on a big-endian host the oracle hashed the wrong words while
 * port/tree/lib/xxhash_rs.rs, which uses u32/u64::from_le_bytes, hashed the
 * right ones.
 *
 * MEASURED, first big-endian run of this harness (s390x under qemu-user,
 * 2026-09-04): 17474 mismatches in 2643312 comparisons, ALL of them
 * xxh32/xxh64 and all at length >= 4 -- lengths 0..3 pass because they take
 * the byte-at-a-time tail. The port was correct; this file was not.
 *
 * Conditioned on __BYTE_ORDER__ rather than on the kernel's __LITTLE_ENDIAN
 * for the same reason zstd_entropy's shim is: the shared shim derives one
 * from the other anyway.
 */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define _shim_lib_le32(x) __builtin_bswap32(x)
#  define _shim_lib_le64(x) __builtin_bswap64(x)
#else
#  define _shim_lib_le32(x) (x)
#  define _shim_lib_le64(x) (x)
#endif

static inline u32 get_unaligned_le32(const void *p)
{
	u32 v;

	memcpy(&v, p, sizeof(v));
	return _shim_lib_le32(v);
}
static inline u64 get_unaligned_le64(const void *p)
{
	u64 v;

	memcpy(&v, p, sizeof(v));
	return _shim_lib_le64(v);
}
static inline void put_unaligned_le32(u32 v, void *p)
{
	u32 t = _shim_lib_le32(v);

	memcpy(p, &t, sizeof(t));
}
static inline void put_unaligned_le64(u64 v, void *p)
{
	u64 t = _shim_lib_le64(v);

	memcpy(p, &t, sizeof(t));
}
/* Generic, for every width. An earlier version handled only 8 and 4 bytes
 * and silently returned 0 for 2 -- which showed up as the port "failing" at
 * lengths 2, 3, 6 and 7. The shim was wrong, not the port. */
#define get_unaligned(p) ({ __typeof__(*(p)) _v_; memcpy(&_v_, (p), sizeof(_v_)); _v_; })
#define put_unaligned(v, p) memcpy((p), &(v), sizeof(v))
#endif
