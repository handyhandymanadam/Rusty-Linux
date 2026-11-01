/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_PROPERTY_H
#define _SHIM_VSPRINTF_LINUX_PROPERTY_H
/*
 * fwnode_string()/fwnode_full_name_string() (%pfw) is deferred --
 * unexercised by this harness's corpus. Minimal stand-ins.
 */
struct fwnode_handle;

static inline struct fwnode_handle *of_fwnode_handle(struct device_node *dn) { return 0; }
static inline int fwnode_count_parents(const struct fwnode_handle *fwnode) { return 0; }
static inline struct fwnode_handle *fwnode_get_nth_parent(struct fwnode_handle *fwnode, unsigned int depth) { return 0; }
static inline const char *fwnode_get_name(const struct fwnode_handle *fwnode) { return ""; }
static inline const char *fwnode_get_name_prefix(const struct fwnode_handle *fwnode) { return ""; }
static inline void fwnode_handle_put(struct fwnode_handle *fwnode) {}

#endif
