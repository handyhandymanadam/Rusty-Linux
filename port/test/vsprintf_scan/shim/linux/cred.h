/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_VSPRINTF_LINUX_CRED_H
#define _SHIM_VSPRINTF_LINUX_CRED_H
/*
 * restricted_pointer() (%pK) is its own deferred seam, not exercised by
 * this harness's corpus at all -- see vsprintf_rs.rs's module doc. Minimal
 * stand-ins, just enough to compile; never actually reached.
 */
typedef struct { unsigned int val; } kuid_t;
typedef struct { unsigned int val; } kgid_t;

struct cred {
	kuid_t uid, euid;
	kgid_t gid, egid;
};

struct task_struct;
#define current ((struct task_struct *)0)
#define CAP_SYSLOG 34

static inline bool uid_eq(kuid_t a, kuid_t b) { return a.val == b.val; }
static inline bool gid_eq(kgid_t a, kgid_t b) { return a.val == b.val; }
static inline const struct cred *current_cred(void) { return 0; }
static inline bool has_capability_noaudit(struct task_struct *t, int cap) { return false; }

static inline bool in_hardirq(void) { return false; }
static inline bool in_serving_softirq(void) { return false; }
static inline bool in_nmi(void) { return false; }

#endif
