/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_COMPILER_H
#define _SHIM_VSPRINTF_LINUX_COMPILER_H
/*
 * Real definition, include/linux/compiler_attributes.h. Missing entirely
 * before, which meant `} __packed;` after `struct printf_spec` was parsed
 * as a separate (implicit-int) tentative declaration of an identifier
 * named `__packed`, not an attribute -- harmless as long as only one
 * translation unit in the link had it (Island A), but a real duplicate-
 * symbol collision once a second one (Island C's "mine" arm) did too. Also
 * meant `struct printf_spec` was never actually `__attribute__((packed))`
 * in this harness at all, silently passing its own `static_assert(sizeof
 * (...) == 8)` only because this struct's fields (u8, u8, i16, i32) need
 * no padding on this host's natural alignment regardless of packing.
 */
#define __packed __attribute__((packed))
#endif
