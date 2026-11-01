/* Userspace stand-in. deftree.c only uses bitrev32(); both the real table
 * path and the arithmetic constant-folded path are proven-equivalent (that
 * is the whole reason bitrev.h picks between them via __builtin_constant_p),
 * so this shim always uses the arithmetic form -- no byte_rev_table to link. */
#ifndef _SHIM_LINUX_BITREV_H
#define _SHIM_LINUX_BITREV_H

#include <stdint.h>

#ifndef _SHIM_U32_DEFINED
#define _SHIM_U32_DEFINED
typedef uint32_t u32;
#endif

static inline uint32_t bitrev32(uint32_t x)
{
    x = (x >> 16) | (x << 16);
    x = ((x & 0xFF00FF00u) >> 8) | ((x & 0x00FF00FFu) << 8);
    x = ((x & 0xF0F0F0F0u) >> 4) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x & 0xCCCCCCCCu) >> 2) | ((x & 0x33333333u) << 2);
    x = ((x & 0xAAAAAAAAu) >> 1) | ((x & 0x55555555u) << 1);
    return x;
}

#endif
