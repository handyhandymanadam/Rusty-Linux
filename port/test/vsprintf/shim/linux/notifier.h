/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_NOTIFIER_H
#define _SHIM_VSPRINTF_LINUX_NOTIFIER_H
/* Boot-param/init machinery -- not called by this harness. */
#define NOTIFY_DONE 0

struct notifier_block {
	int (*notifier_call)(struct notifier_block *, unsigned long, void *);
};

static inline void execute_with_initialized_rng(struct notifier_block *nb) {}

#endif
