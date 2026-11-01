/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_DEVICE_H
#define _SHIM_LINUX_DEVICE_H
#include <stddef.h>

struct device;

typedef unsigned int gfp_t;
#define NUMA_NO_NODE (-1)

typedef void (*dr_release_t)(struct device *dev, void *res);
extern void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp, int nid);
#define devres_alloc(release, size, gfp) __devres_alloc_node(release, size, gfp, NUMA_NO_NODE)
extern void devres_add(struct device *dev, void *res);
extern void devres_free(void *res);

#endif
