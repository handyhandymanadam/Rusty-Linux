/* SPDX-License-Identifier: GPL-2.0 */
/* zstd_entropy shim: <linux/unaligned.h>.
 *
 * The kernel's generic implementation, transcribed. It is the packed-struct
 * form from <linux/unaligned/packed_struct.h> plus the le/be wrappers from
 * <linux/unaligned.h> -- and it is transcribed rather than approximated with
 * memcpy because these are the only routines through which lib/zstd touches
 * memory, so any difference between what the oracle compiles and what the
 * kernel compiles lands squarely on the code under test.
 *
 * The byteswaps are conditioned on __BYTE_ORDER__ rather than on the kernel's
 * __LITTLE_ENDIAN, because <linux/kernel.h>'s shared shim derives the latter
 * from the former anyway and there is no reason to launder it twice.
 */
#ifndef _SHIM_ZSTD_LINUX_UNALIGNED_H
#define _SHIM_ZSTD_LINUX_UNALIGNED_H

#include <stdint.h>
#include <linux/swab.h>

#define __get_unaligned_t(type, ptr) ({						\
	const struct { type x; } __attribute__((__packed__)) *__get_pptr =	\
		(__typeof__(__get_pptr))(ptr);					\
	__get_pptr->x;								\
})

#define __put_unaligned_t(type, val, ptr) do {					\
	struct { type x; } __attribute__((__packed__)) *__put_pptr =		\
		(__typeof__(__put_pptr))(ptr);					\
	__put_pptr->x = (val);							\
} while (0)

#define get_unaligned(ptr)	__get_unaligned_t(__typeof__(*(ptr)), (ptr))
#define put_unaligned(val, ptr)	__put_unaligned_t(__typeof__(*(ptr)), (val), (ptr))

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define _shim_le16(x) swab16(x)
#  define _shim_le32(x) swab32(x)
#  define _shim_le64(x) swab64(x)
#  define _shim_be16(x) (x)
#  define _shim_be32(x) (x)
#  define _shim_be64(x) (x)
#else
#  define _shim_le16(x) (x)
#  define _shim_le32(x) (x)
#  define _shim_le64(x) (x)
#  define _shim_be16(x) swab16(x)
#  define _shim_be32(x) swab32(x)
#  define _shim_be64(x) swab64(x)
#endif

static inline uint16_t get_unaligned_le16(const void *p)
{ return _shim_le16(__get_unaligned_t(uint16_t, p)); }
static inline uint32_t get_unaligned_le32(const void *p)
{ return _shim_le32(__get_unaligned_t(uint32_t, p)); }
static inline uint64_t get_unaligned_le64(const void *p)
{ return _shim_le64(__get_unaligned_t(uint64_t, p)); }

static inline void put_unaligned_le16(uint16_t v, void *p)
{ __put_unaligned_t(uint16_t, _shim_le16(v), p); }
static inline void put_unaligned_le32(uint32_t v, void *p)
{ __put_unaligned_t(uint32_t, _shim_le32(v), p); }
static inline void put_unaligned_le64(uint64_t v, void *p)
{ __put_unaligned_t(uint64_t, _shim_le64(v), p); }

static inline uint16_t get_unaligned_be16(const void *p)
{ return _shim_be16(__get_unaligned_t(uint16_t, p)); }
static inline uint32_t get_unaligned_be32(const void *p)
{ return _shim_be32(__get_unaligned_t(uint32_t, p)); }
static inline uint64_t get_unaligned_be64(const void *p)
{ return _shim_be64(__get_unaligned_t(uint64_t, p)); }

static inline void put_unaligned_be16(uint16_t v, void *p)
{ __put_unaligned_t(uint16_t, _shim_be16(v), p); }
static inline void put_unaligned_be32(uint32_t v, void *p)
{ __put_unaligned_t(uint32_t, _shim_be32(v), p); }
static inline void put_unaligned_be64(uint64_t v, void *p)
{ __put_unaligned_t(uint64_t, _shim_be64(v), p); }

#endif
