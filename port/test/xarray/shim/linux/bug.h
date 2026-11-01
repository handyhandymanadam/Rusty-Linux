/* SPDX-License-Identifier: GPL-2.0-only */
/* lib/xarray.c reaches WARN_ON only through xarray.h's xa_mk_value() and
 * xas_split_alloc(); XA_DEBUG stays undefined here (see xarray.h's own
 * XA_NODE_BUG_ON/XA_BUG_ON #else arm) so BUG()/xa_dump_node() are never
 * reached and do not need real bodies. */
#ifndef _SHIM_XARRAY_LINUX_BUG_H
#define _SHIM_XARRAY_LINUX_BUG_H
#include <stdio.h>
#include <stdlib.h>

#define WARN_ON(cond) ({ \
	int __ret = !!(cond); \
	if (__ret) fprintf(stderr, "WARN_ON(%s) at %s:%d\n", #cond, __FILE__, __LINE__); \
	__ret; \
})
#define WARN_ON_ONCE(cond) WARN_ON(cond)
#define BUG() do { fprintf(stderr, "BUG at %s:%d\n", __FILE__, __LINE__); abort(); } while (0)
#define BUG_ON(cond) do { if (cond) BUG(); } while (0)

#endif
