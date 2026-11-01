// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (kernel/ucount.c, 6.18.49): the counter walks up the namespace chain (inc_ucount, dec_ucount, the rlimit counters, is_rlimit_overlimit) are in ucount_rs.rs.
 * This file keeps the hash table, its lock and RCU lookups (alloc_ucounts, put_ucounts), the sysctl tables and the initcall as upstream has them, the entry points as thunks, the
 * field offsets (struct ucounts and struct user_namespace depend on the configuration) and one WARN_ON_ONCE wrapper per site. Upstream's whole file is installed as
 * ucount_norust.c for CONFIG_RUST=n.
 */

#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/hash.h>
#include <linux/kmemleak.h>
#include <linux/user_namespace.h>

struct ucounts init_ucounts = {
	.ns    = &init_user_ns,
	.uid   = GLOBAL_ROOT_UID,
	.count = RCUREF_INIT(1),
};

#define UCOUNTS_HASHTABLE_BITS 10
#define UCOUNTS_HASHTABLE_ENTRIES (1 << UCOUNTS_HASHTABLE_BITS)
static struct hlist_nulls_head ucounts_hashtable[UCOUNTS_HASHTABLE_ENTRIES] = {
	[0 ... UCOUNTS_HASHTABLE_ENTRIES - 1] = HLIST_NULLS_HEAD_INIT(0)
};
static DEFINE_SPINLOCK(ucounts_lock);

/* The counter walks are in ucount_rs.rs. */
struct ucounts *rust_inc_ucount(struct user_namespace *ns, u32 uid, int type);
void rust_dec_ucount(struct ucounts *ucounts, int type);
long rust_inc_rlimit_ucounts(struct ucounts *ucounts, int type, long v);
bool rust_dec_rlimit_ucounts(struct ucounts *ucounts, int type, long v);
void rust_dec_rlimit_put_ucounts(struct ucounts *ucounts, int type);
long rust_inc_rlimit_get_ucounts(struct ucounts *ucounts, int type, bool override_rlimit);
bool rust_is_rlimit_overlimit(struct ucounts *ucounts, int type, u64 rlimit);

extern const size_t rust_uc_off_ns, rust_uc_off_ucount, rust_uc_off_rlimit, rust_uc_off_ns_ucounts, rust_uc_off_ns_ucount_max, rust_uc_off_ns_rlimit_max;
const size_t rust_uc_off_ns = offsetof(struct ucounts, ns);
const size_t rust_uc_off_ucount = offsetof(struct ucounts, ucount);
const size_t rust_uc_off_rlimit = offsetof(struct ucounts, rlimit);
const size_t rust_uc_off_ns_ucounts = offsetof(struct user_namespace, ucounts);
const size_t rust_uc_off_ns_ucount_max = offsetof(struct user_namespace, ucount_max);
const size_t rust_uc_off_ns_rlimit_max = offsetof(struct user_namespace, rlimit_max);
static_assert(sizeof(atomic_long_t) == 8 && sizeof(((struct user_namespace *)0)->ucount_max[0]) == 8 && sizeof(((struct user_namespace *)0)->rlimit_max[0]) == 8);

struct ucounts *rust_uc_alloc(struct user_namespace *ns, u32 uid);
void rust_uc_put(struct ucounts *u);
struct ucounts *rust_uc_get(struct ucounts *u);
void rust_uc_warn_dec_ucount(void);
void rust_uc_warn_dec_rlimit(void);
void rust_uc_warn_do_dec(void);
void rust_uc_warn_unwind(void);
struct ucounts *rust_uc_alloc(struct user_namespace *ns, u32 uid) { return alloc_ucounts(ns, KUIDT_INIT(uid)); }
void rust_uc_put(struct ucounts *u) { put_ucounts(u); }
struct ucounts *rust_uc_get(struct ucounts *u) { return get_ucounts(u); }
/* one wrapper per WARN_ON_ONCE site: the once-flag is per site */
void rust_uc_warn_dec_ucount(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_dec_rlimit(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_do_dec(void) { WARN_ON_ONCE(1); }
void rust_uc_warn_unwind(void) { WARN_ON_ONCE(1); }

#define ucounts_hashfn(ns, uid)						\
	hash_long((unsigned long)__kuid_val(uid) + (unsigned long)(ns), \
		  UCOUNTS_HASHTABLE_BITS)
#define ucounts_hashentry(ns, uid)	\
	(ucounts_hashtable + ucounts_hashfn(ns, uid))

#ifdef CONFIG_SYSCTL
static struct ctl_table_set *
set_lookup(struct ctl_table_root *root)
{
	return &current_user_ns()->set;
}

static int set_is_seen(struct ctl_table_set *set)
{
	return &current_user_ns()->set == set;
}

static int set_permissions(struct ctl_table_header *head,
			   const struct ctl_table *table)
{
	struct user_namespace *user_ns =
		container_of(head->set, struct user_namespace, set);
	int mode;

	/* Allow users with CAP_SYS_RESOURCE unrestrained access */
	if (ns_capable_noaudit(user_ns, CAP_SYS_RESOURCE))
		mode = (table->mode & S_IRWXU) >> 6;
	else
	/* Allow all others at most read-only access */
		mode = table->mode & S_IROTH;
	return (mode << 6) | (mode << 3) | mode;
}

static struct ctl_table_root set_root = {
	.lookup = set_lookup,
	.permissions = set_permissions,
};

static long ue_zero = 0;
static long ue_int_max = INT_MAX;

#define UCOUNT_ENTRY(name)					\
	{							\
		.procname	= name,				\
		.maxlen		= sizeof(long),			\
		.mode		= 0644,				\
		.proc_handler	= proc_doulongvec_minmax,	\
		.extra1		= &ue_zero,			\
		.extra2		= &ue_int_max,			\
	}
static const struct ctl_table user_table[] = {
	UCOUNT_ENTRY("max_user_namespaces"),
	UCOUNT_ENTRY("max_pid_namespaces"),
	UCOUNT_ENTRY("max_uts_namespaces"),
	UCOUNT_ENTRY("max_ipc_namespaces"),
	UCOUNT_ENTRY("max_net_namespaces"),
	UCOUNT_ENTRY("max_mnt_namespaces"),
	UCOUNT_ENTRY("max_cgroup_namespaces"),
	UCOUNT_ENTRY("max_time_namespaces"),
#ifdef CONFIG_INOTIFY_USER
	UCOUNT_ENTRY("max_inotify_instances"),
	UCOUNT_ENTRY("max_inotify_watches"),
#endif
#ifdef CONFIG_FANOTIFY
	UCOUNT_ENTRY("max_fanotify_groups"),
	UCOUNT_ENTRY("max_fanotify_marks"),
#endif
};
#endif /* CONFIG_SYSCTL */

bool setup_userns_sysctls(struct user_namespace *ns)
{
#ifdef CONFIG_SYSCTL
	struct ctl_table *tbl;

	BUILD_BUG_ON(ARRAY_SIZE(user_table) != UCOUNT_COUNTS);
	setup_sysctl_set(&ns->set, &set_root, set_is_seen);
	tbl = kmemdup(user_table, sizeof(user_table), GFP_KERNEL);
	if (tbl) {
		int i;
		for (i = 0; i < UCOUNT_COUNTS; i++) {
			tbl[i].data = &ns->ucount_max[i];
		}
		ns->sysctls = __register_sysctl_table(&ns->set, "user", tbl,
						      ARRAY_SIZE(user_table));
	}
	if (!ns->sysctls) {
		kfree(tbl);
		retire_sysctl_set(&ns->set);
		return false;
	}
#endif
	return true;
}

void retire_userns_sysctls(struct user_namespace *ns)
{
#ifdef CONFIG_SYSCTL
	const struct ctl_table *tbl;

	tbl = ns->sysctls->ctl_table_arg;
	unregister_sysctl_table(ns->sysctls);
	retire_sysctl_set(&ns->set);
	kfree(tbl);
#endif
}

static struct ucounts *find_ucounts(struct user_namespace *ns, kuid_t uid,
				    struct hlist_nulls_head *hashent)
{
	struct ucounts *ucounts;
	struct hlist_nulls_node *pos;

	guard(rcu)();
	hlist_nulls_for_each_entry_rcu(ucounts, pos, hashent, node) {
		if (uid_eq(ucounts->uid, uid) && (ucounts->ns == ns)) {
			if (rcuref_get(&ucounts->count))
				return ucounts;
		}
	}
	return NULL;
}

static void hlist_add_ucounts(struct ucounts *ucounts)
{
	struct hlist_nulls_head *hashent = ucounts_hashentry(ucounts->ns, ucounts->uid);

	spin_lock_irq(&ucounts_lock);
	hlist_nulls_add_head_rcu(&ucounts->node, hashent);
	spin_unlock_irq(&ucounts_lock);
}

struct ucounts *alloc_ucounts(struct user_namespace *ns, kuid_t uid)
{
	struct hlist_nulls_head *hashent = ucounts_hashentry(ns, uid);
	struct ucounts *ucounts, *new;

	ucounts = find_ucounts(ns, uid, hashent);
	if (ucounts)
		return ucounts;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;

	new->ns = ns;
	new->uid = uid;
	rcuref_init(&new->count, 1);

	spin_lock_irq(&ucounts_lock);
	ucounts = find_ucounts(ns, uid, hashent);
	if (ucounts) {
		spin_unlock_irq(&ucounts_lock);
		kfree(new);
		return ucounts;
	}

	hlist_nulls_add_head_rcu(&new->node, hashent);
	get_user_ns(new->ns);
	spin_unlock_irq(&ucounts_lock);
	return new;
}

void put_ucounts(struct ucounts *ucounts)
{
	unsigned long flags;

	if (rcuref_put(&ucounts->count)) {
		spin_lock_irqsave(&ucounts_lock, flags);
		hlist_nulls_del_rcu(&ucounts->node);
		spin_unlock_irqrestore(&ucounts_lock, flags);

		put_user_ns(ucounts->ns);
		kfree_rcu(ucounts, rcu);
	}
}


struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid,
			   enum ucount_type type)
{
	return rust_inc_ucount(ns, __kuid_val(uid), type);
}

void dec_ucount(struct ucounts *ucounts, enum ucount_type type)
{
	rust_dec_ucount(ucounts, type);
}

long inc_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	return rust_inc_rlimit_ucounts(ucounts, type, v);
}

bool dec_rlimit_ucounts(struct ucounts *ucounts, enum rlimit_type type, long v)
{
	return rust_dec_rlimit_ucounts(ucounts, type, v);
}


void dec_rlimit_put_ucounts(struct ucounts *ucounts, enum rlimit_type type)
{
	rust_dec_rlimit_put_ucounts(ucounts, type);
}

long inc_rlimit_get_ucounts(struct ucounts *ucounts, enum rlimit_type type,
			    bool override_rlimit)
{
	return rust_inc_rlimit_get_ucounts(ucounts, type, override_rlimit);
}

bool is_rlimit_overlimit(struct ucounts *ucounts, enum rlimit_type type, unsigned long rlimit)
{
	return rust_is_rlimit_overlimit(ucounts, type, rlimit);
}

static __init int user_namespace_sysctl_init(void)
{
#ifdef CONFIG_SYSCTL
	static struct ctl_table_header *user_header;
	static struct ctl_table empty[1];
	/*
	 * It is necessary to register the user directory in the
	 * default set so that registrations in the child sets work
	 * properly.
	 */
	user_header = register_sysctl_sz("user", empty, 0);
	kmemleak_ignore(user_header);
	BUG_ON(!user_header);
	BUG_ON(!setup_userns_sysctls(&init_user_ns));
#endif
	hlist_add_ucounts(&init_ucounts);
	inc_rlimit_ucounts(&init_ucounts, UCOUNT_RLIMIT_NPROC, 1);
	return 0;
}
subsys_initcall(user_namespace_sysctl_init);
