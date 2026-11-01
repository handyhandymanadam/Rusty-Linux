/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_MATH64_H
#define _SHIM_LINUX_MATH64_H
#include <stdint.h>
/* BITS_PER_LONG == 64 on this host: do_div is plain division/remainder. */
#define do_div(n, base) \
    ({ \
        uint32_t __rem = (uint32_t)((n) % (base)); \
        (n) = (n) / (base); \
        __rem; \
    })
#endif
