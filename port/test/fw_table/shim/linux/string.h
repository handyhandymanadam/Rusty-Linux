/* SPDX-License-Identifier: GPL-2.0-only */
/* strncmp() is libc's here. Both arms compare the same four signature bytes
 * with the same early-stop-at-NUL semantics -- the Rust reproduces strncmp
 * rather than doing a flat 4-byte compare, and this is what it is compared
 * against. */
#ifndef _SHIM_FW_TABLE_LINUX_STRING_H
#define _SHIM_FW_TABLE_LINUX_STRING_H
#include <string.h>
#endif
