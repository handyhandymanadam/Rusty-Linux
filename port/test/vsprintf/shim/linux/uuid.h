/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_UUID_H
#define _SHIM_VSPRINTF_LINUX_UUID_H
#include <linux/types.h>

#define UUID_STRING_LEN 36

/* Real values, lib/uuid.c. Defined once in stubs.c, shared by both the
 * REF and RS arms (RS reads them via the same extern names). */
extern const u8 guid_index[16];
extern const u8 uuid_index[16];

#endif
