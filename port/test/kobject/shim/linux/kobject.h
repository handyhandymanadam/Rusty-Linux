/* shim for the kobject differential: just enough of the kernel for pristine lib/kobject.c and kobject_glue.c over kobject_rs.rs. The layouts of struct kobject, kobj_type, kobj_ns_type_operations match what
 * kobject_glue.c static_asserts (and what the real header has on x86-64 without CONFIG_DEBUG_KOBJECT_RELEASE). */
#ifndef SH_KOBJECT_H
#define SH_KOBJECT_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <linux/export.h>

#define __printf(a, b)
#define __must_check
#define __randomize_layout
#define KERN_ERR ""
#define KERN_WARNING ""
#define GFP_KERNEL 0xcc0u
#define GFP_NOWAIT 0x0u
typedef unsigned int gfp_t;
typedef struct { unsigned v; } kuid_t;
typedef struct { unsigned v; } kgid_t;
#define GLOBAL_ROOT_UID ((kuid_t){ 0 })
#define GLOBAL_ROOT_GID ((kgid_t){ 0 })
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define list_entry(p, t, m) container_of(p, t, m)

struct list_head { struct list_head *next, *prev; };
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *p, struct list_head *x) { x->prev = n; n->next = x; n->prev = p; p->next = n; }
static inline void list_add_tail(struct list_head *n, struct list_head *h) { __list_add(n, h->prev, h); }
static inline void list_del_init(struct list_head *e) { e->prev->next = e->next; e->next->prev = e->prev; INIT_LIST_HEAD(e); }
#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof__(*pos), member); &pos->member != (head); pos = list_entry(pos->member.next, __typeof__(*pos), member))

extern long lock_ops, lock_depth;
typedef struct { int locked; } spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x = { 0 }
#define spin_lock_init(l) do { (l)->locked = 0; } while (0)
#define spin_lock(l) do { if ((l)->locked) { printf("DEADLOCK\n"); abort(); } (l)->locked = 1; lock_ops++; lock_depth++; } while (0)
#define spin_unlock(l) do { (l)->locked = 0; lock_depth--; } while (0)

extern int warn_count;
typedef struct { int refs; } refcount_t;
struct kref { refcount_t refcount; };
static inline void kref_init(struct kref *k) { k->refcount.refs = 1; }
static inline void kref_get(struct kref *k) { if (k->refcount.refs++ <= 0) warn_count += 1000; }
static inline bool kref_get_unless_zero(struct kref *k) { if (k->refcount.refs == 0) return false; k->refcount.refs++; return true; }
static inline int kref_put(struct kref *k, void (*release)(struct kref *)) { int o = --k->refcount.refs; if (o < 0) warn_count += 1000; if (o == 0) { release(k); return 1; } return 0; }

void klog(const char *tag, const char *fmt, ...);
#define pr_err(fmt, ...) klog("pr_err", pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) klog("pr_warn", pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) klog("pr_info", pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) do { } while (0)
#define WARN(c, fmt, ...) ({ int __r = !!(c); if (__r) { warn_count++; klog("WARN", fmt, ##__VA_ARGS__); } __r; })
#define BUG_ON(c) do { if (c) { klog("BUG", "BUG_ON\n"); fflush(stdout); abort(); } } while (0)
#define BUG() do { klog("BUG", "BUG()\n"); fflush(stdout); abort(); } while (0)
#define dump_stack_lvl(l) klog("dump_stack", "\n")
#define KBUILD_MODNAME "kobject"

void *kmalloc(size_t n, gfp_t g); void *kzalloc(size_t n, gfp_t g); void kfree(const void *p);
char *kstrdup(const char *s, gfp_t g); const char *kstrdup_const(const char *s, gfp_t g); void kfree_const(const void *p);
const char *kvasprintf_const(gfp_t g, const char *fmt, va_list ap); char *strreplace(char *s, char old, char new);

struct kernfs_node; struct attribute_group; struct sock; struct kobject; struct kset; struct kobj_uevent_env;
enum kobject_action { KOBJ_ADD, KOBJ_REMOVE, KOBJ_CHANGE, KOBJ_MOVE, KOBJ_ONLINE, KOBJ_OFFLINE, KOBJ_BIND, KOBJ_UNBIND };
enum kobj_ns_type { KOBJ_NS_TYPE_NONE = 0, KOBJ_NS_TYPE_NET, KOBJ_NS_TYPES };

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)(void);
	void *(*grab_current_ns)(void);
	const void *(*netlink_ns)(struct sock *sk);
	const void *(*initial_ns)(void);
	void (*drop_ns)(void *);
};
int kobj_ns_type_register(const struct kobj_ns_type_operations *ops);
int kobj_ns_type_registered(enum kobj_ns_type type);
const struct kobj_ns_type_operations *kobj_child_ns_ops(const struct kobject *parent);
const struct kobj_ns_type_operations *kobj_ns_ops(const struct kobject *kobj);
bool kobj_ns_current_may_mount(enum kobj_ns_type type);
void *kobj_ns_grab_current(enum kobj_ns_type type);
void kobj_ns_drop(enum kobj_ns_type type, void *ns);

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized:1;
	unsigned int state_in_sysfs:1;
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;
};
struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations *(*child_ns_type)(const struct kobject *kobj);
	const void *(*namespace)(const struct kobject *kobj);
	void (*get_ownership)(const struct kobject *kobj, kuid_t *uid, kgid_t *gid);
};
struct attribute { const char *name; unsigned short mode; };
struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
};
struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};
struct kset_uevent_ops { int unused; };
struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};
extern const struct sysfs_ops kobj_sysfs_ops;

static inline const char *kobject_name(const struct kobject *kobj) { return kobj->name; }
static inline const struct kobj_type *get_ktype(const struct kobject *kobj) { return kobj->ktype; }
const void *kobject_namespace(const struct kobject *kobj);
void kobject_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid);
char *kobject_get_path(const struct kobject *kobj, gfp_t flag);
int kobject_set_name(struct kobject *kobj, const char *name, ...);
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt, va_list vargs);
void kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
int kobject_add(struct kobject *kobj, struct kobject *parent, const char *fmt, ...);
int kobject_init_and_add(struct kobject *kobj, const struct kobj_type *ktype, struct kobject *parent, const char *fmt, ...);
void kobject_del(struct kobject *kobj);
struct kobject *kobject_create_and_add(const char *name, struct kobject *parent);
int kobject_rename(struct kobject *, const char *new_name);
int kobject_move(struct kobject *, struct kobject *);
struct kobject *kobject_get(struct kobject *kobj);
struct kobject *kobject_get_unless_zero(struct kobject *kobj);
void kobject_put(struct kobject *kobj);
void kset_init(struct kset *kset);
int kset_register(struct kset *kset);
void kset_unregister(struct kset *kset);
struct kset *kset_create_and_add(const char *name, const struct kset_uevent_ops *u, struct kobject *parent_kobj);
static inline struct kset *to_kset(struct kobject *kobj) { return kobj ? container_of(kobj, struct kset, kobj) : NULL; }
static inline struct kset *kset_get(struct kset *k) { return k ? to_kset(kobject_get(&k->kobj)) : NULL; }
static inline void kset_put(struct kset *k) { kobject_put(&k->kobj); }
struct kobject *kset_find_obj(struct kset *, const char *);
int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action, char *envp[]);

int sysfs_create_dir_ns(struct kobject *kobj, const void *ns);
int sysfs_create_groups(struct kobject *kobj, const struct attribute_group **groups);
void sysfs_remove_groups(struct kobject *kobj, const struct attribute_group **groups);
void sysfs_remove_dir(struct kobject *kobj);
void sysfs_get(struct kernfs_node *sd); void sysfs_put(struct kernfs_node *sd); void sysfs_enable_ns(struct kernfs_node *sd);
int sysfs_rename_dir_ns(struct kobject *kobj, const char *new_name, const void *new_ns);
int sysfs_move_dir_ns(struct kobject *kobj, struct kobject *new_parent_kobj, const void *new_ns);
#endif
