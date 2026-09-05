/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_COMPILER_H
#define _SHIM_LINUX_COMPILER_H
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef __attribute_const__
#define __attribute_const__ __attribute__((const))
#endif
#define unlikely(x) (x)
#define likely(x) (x)
#endif
