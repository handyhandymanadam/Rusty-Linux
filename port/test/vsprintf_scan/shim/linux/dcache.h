/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_DCACHE_H
#define _SHIM_VSPRINTF_LINUX_DCACHE_H
/*
 * dentry_name()/file_dentry_name() (the %pd/%pD seam) are deferred --
 * this harness's corpus never exercises them (see vsprintf_rs.rs's own
 * module doc for why). Minimal stand-ins, just enough to compile.
 */
struct qstr {
	const char *name;
};

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
};

struct path {
	struct dentry *dentry;
};

struct file {
	struct path f_path;
};

static inline void rcu_read_lock(void) {}
static inline void rcu_read_unlock(void) {}

#endif
