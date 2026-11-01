/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_OF_H
#define _SHIM_VSPRINTF_LINUX_OF_H
/*
 * device_node_string() (%pOF) is deferred and dead in both this project's
 * real configs (CONFIG_OF unset, checked directly against both
 * .config's) -- unexercised by this harness's corpus. Minimal stand-ins.
 */
struct device_node {
	unsigned int phandle;
};
struct property { const char *name; };

#define OF_DYNAMIC 0
#define OF_DETACHED 1
#define OF_POPULATED 2
#define OF_POPULATED_BUS 3

static inline bool of_node_check_flag(const struct device_node *n, int f) { return false; }
static inline int of_property_read_string(struct device_node *np, const char *name, const char **out)
{
	return -1;
}
#define of_property_for_each_string(np, propname, prop, s) \
	for ((prop) = (void *)0, (s) = (void *)0; 0; )

#endif
