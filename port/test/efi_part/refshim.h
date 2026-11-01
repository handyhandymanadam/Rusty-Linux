/* Stand-ins for what the pristine slice of block/partitions/efi.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64; typedef uint32_t uint32_t_; typedef u16 __le16; typedef u32 __le32; typedef u64 __le64; typedef u64 sector_t;
#define __packed __attribute__((packed))
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define static_assert(x) _Static_assert(x, #x)
#define pr_debug(...) do { } while (0)
#define pr_warn(...) printf(__VA_ARGS__)
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
extern unsigned int g_ssz; extern u64 g_lastlba;
struct gendisk_ { void *queue; };
struct parsed_partitions { struct gendisk_ *disk; };
extern struct parsed_partitions g_state;
#define queue_logical_block_size(q) (g_ssz)
static inline u64 last_lba(struct gendisk_ *d) { return g_lastlba; }
static inline u32 crc32_(u32 crc, const void *buf, unsigned long len)
{
	const u8 *p = buf; unsigned long i; int k;
	for (i = 0; i < len; i++) { crc ^= p[i]; for (k = 0; k < 8; k++) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0); }
	return crc;
}
#define crc32(seed, buf, len) crc32_((u32)(seed), buf, len)
static inline u32 efi_crc32(const void *buf, unsigned long len) { return (crc32(~0L, buf, len) ^ ~0L); }
#endif
