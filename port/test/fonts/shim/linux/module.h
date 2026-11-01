/* SPDX-License-Identifier: GPL-2.0 */
/* Userspace stand-in: EXPORT_SYMBOL() is a no-op here, the real kernel
 * macro's job (module symbol table registration) has no counterpart in
 * a plain userspace binary -- the symbol is exported by ordinary
 * external C linkage regardless. */
#ifndef _SHIM_FONTS_LINUX_MODULE_H
#define _SHIM_FONTS_LINUX_MODULE_H
#define EXPORT_SYMBOL(sym)
#endif
