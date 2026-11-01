/* Stand-ins for what the pristine slice of net/ethtool/bitset.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t u32;
#define ETH_GSTRING_LEN 32
#define NLA_HDRLEN 4
#define NLA_ALIGN(len) (((len) + 3) & ~3)
static inline int nla_total_size(int payload) { return NLA_ALIGN(payload + NLA_HDRLEN); }
static inline int ethnl_strz_size(const char *s) { return nla_total_size(strnlen(s, ETH_GSTRING_LEN) + 1); }
typedef const char (*const ethnl_string_array_t)[ETH_GSTRING_LEN];
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
static inline void *memchr_inv(const void *start, int c, size_t bytes)
{
	const unsigned char *p = start; size_t i;
	for (i = 0; i < bytes; i++) if (p[i] != (unsigned char)c) return (void *)(p + i);
	return NULL;
}
#endif
