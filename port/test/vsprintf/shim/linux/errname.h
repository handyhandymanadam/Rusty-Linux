/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_ERRNAME_H
#define _SHIM_LINUX_ERRNAME_H
#include <stddef.h>
/* CONFIG_SYMBOLIC_ERRNAME left undefined -- matches the real header's
 * #else arm (NULL always), same as build-fast's real config. */
static inline const char *errname(int err)
{
	return NULL;
}
#endif
