/* Stand-ins for what the pristine slice of fs/unicode/utf8-core.c uses (utf8n.h comes from the pristine tree, linux/unicode.h from the shim of the utf8_norm test). */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define EINVAL 22
#define EXPORT_SYMBOL(x)
struct qstr { u32 hash; u32 len; const unsigned char *name; };
#define init_name_hash(salt) (unsigned long)(salt)
static inline unsigned long partial_name_hash(unsigned long c, unsigned long prevhash) { return (prevhash + (c << 4) + (c >> 4)) * 11; }
static inline unsigned int end_name_hash(unsigned long hash) { return (unsigned int)(((u64)hash * 0x61C8864680B583EBull) >> (64 - 32)); }
#endif
