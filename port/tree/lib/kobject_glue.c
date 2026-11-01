// SPDX-License-Identifier: GPL-2.0
/*
 * kobject.c - library routines for handling generic kernel objects
 *
 * Copyright (c) 2002-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2006-2007 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2007 Novell Inc.
 *
 * Please see the file Documentation/core-api/kobject.rst for critical information
 * about using the kobject interface.
 *
 * RUST PORT (lib/kobject.c, 6.18.49): path building, kset join/leave, add/del/rename/move, the reference counting and cleanup, kset_register/unregister/find_obj
 * and the namespace-type table are in kobject_rs.rs. This file keeps what takes a va_list or `...` (kobject_set_name*, kobject_add*, kobject_init_and_add,
 * kobject_create*, kset_create*), kset_init() (lockdep key per call site), the static kobj_types and kobj_sysfs_ops, the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition) and the wrappers Rust cannot express: spinlock, kref, list, sysfs, uevent, allocator, the bit-fields of
 * struct kobject, and the WARN/BUG/pr_err sites (messages now name this file -- recorded divergence). pr_debug sites are not carried over: this arm is only built
 * with CONFIG_DEBUG_KOBJECT off, where they compile to nothing. Upstream's whole file is installed as kobject_norust.c for CONFIG_RUST=n.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/random.h>

static_assert(offsetof(struct kobject, name) == 0 && offsetof(struct kobject, entry) == 8 && offsetof(struct kobject, parent) == 24 &&
	      offsetof(struct kobject, kset) == 32 && offsetof(struct kobject, ktype) == 40 && offsetof(struct kobject, sd) == 48);
static_assert(sizeof(struct kobj_type) == 48 && offsetof(struct kobj_type, release) == 0 && offsetof(struct kobj_type, sysfs_ops) == 8 &&
	      offsetof(struct kobj_type, default_groups) == 16 && offsetof(struct kobj_type, child_ns_type) == 24 &&
	      offsetof(struct kobj_type, namespace) == 32 && offsetof(struct kobj_type, get_ownership) == 40);
static_assert(sizeof(struct kobj_ns_type_operations) == 48 && offsetof(struct kobj_ns_type_operations, type) == 0 &&
	      offsetof(struct kobj_ns_type_operations, current_may_mount) == 8 && offsetof(struct kobj_ns_type_operations, grab_current_ns) == 16 &&
	      offsetof(struct kobj_ns_type_operations, netlink_ns) == 24 && offsetof(struct kobj_ns_type_operations, initial_ns) == 32 &&
	      offsetof(struct kobj_ns_type_operations, drop_ns) == 40);
static_assert(KOBJ_ADD == 0 && KOBJ_REMOVE == 1 && KOBJ_MOVE == 3 && KOBJ_NS_TYPE_NONE == 0 && KOBJ_NS_TYPES == 2 && EEXIST == 17 && EBUSY == 16);

/* struct kset is __randomize_layout */
extern const size_t rust_ks_off_list, rust_ks_off_kobj;
const size_t rust_ks_off_list = offsetof(struct kset, list);
const size_t rust_ks_off_kobj = offsetof(struct kset, kobj);

static DEFINE_SPINLOCK(kobj_ns_type_lock);

const void *rust_kobject_namespace(const struct kobject *kobj);
void rust_kobject_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid);
char *rust_kobject_get_path(const struct kobject *kobj, gfp_t gfp_mask);
void rust_kobject_init_internal(struct kobject *kobj);
int rust_kobject_add_internal(struct kobject *kobj);
void rust_kobject_init(struct kobject *kobj, const struct kobj_type *ktype);
int rust_kobject_rename(struct kobject *kobj, const char *new_name);
int rust_kobject_move(struct kobject *kobj, struct kobject *new_parent);
void rust_kobject_del(struct kobject *kobj);
struct kobject *rust_kobject_get(struct kobject *kobj);
struct kobject *rust_kobject_get_unless_zero(struct kobject *kobj);
void rust_kobject_cleanup(struct kobject *kobj);
void rust_kobject_put(struct kobject *kobj);
int rust_kset_register(struct kset *k);
void rust_kset_unregister(struct kset *k);
struct kobject *rust_kset_find_obj(struct kset *kset, const char *name);
int rust_kobj_ns_type_register(const struct kobj_ns_type_operations *ops);
int rust_kobj_ns_type_registered(enum kobj_ns_type type);
const struct kobj_ns_type_operations *rust_kobj_child_ns_ops(const struct kobject *parent);
const struct kobj_ns_type_operations *rust_kobj_ns_ops(const struct kobject *kobj);
bool rust_kobj_ns_current_may_mount(enum kobj_ns_type type);
void *rust_kobj_ns_grab_current(enum kobj_ns_type type);
void rust_kobj_ns_drop(enum kobj_ns_type type, void *ns);

static void kobject_release(struct kref *kref);

void rust_ko_ks_lock(struct kset *k);
void rust_ko_ks_unlock(struct kset *k);
void rust_ko_ns_lock(void);
void rust_ko_ns_unlock(void);
void rust_ko_list_add_tail(struct list_head *new, struct list_head *head);
void rust_ko_list_del_init(struct list_head *entry);
void rust_ko_init_list_head(struct list_head *l);
void rust_ko_kref_init(struct kobject *k);
void rust_ko_kref_get(struct kobject *k);
bool rust_ko_kref_get_unless_zero(struct kobject *k);
void rust_ko_kref_put(struct kobject *k);
void rust_ko_init_state(struct kobject *k);
bool rust_ko_get_initialized(const struct kobject *k);
bool rust_ko_get_in_sysfs(const struct kobject *k);
void rust_ko_set_in_sysfs(struct kobject *k, bool v);
bool rust_ko_get_add_sent(const struct kobject *k);
bool rust_ko_get_remove_sent(const struct kobject *k);
int rust_ko_sysfs_create_dir_ns(struct kobject *k, const void *ns);
int rust_ko_sysfs_create_groups(struct kobject *k, const struct attribute_group **groups);
void rust_ko_sysfs_remove_groups(struct kobject *k, const struct attribute_group **groups);
void rust_ko_sysfs_remove_dir(struct kobject *k);
void rust_ko_sysfs_get(struct kobject *k);
void rust_ko_sysfs_put(struct kernfs_node *sd);
void rust_ko_sysfs_enable_ns(struct kobject *k);
int rust_ko_sysfs_rename_dir_ns(struct kobject *k, const char *new_name, const void *ns);
int rust_ko_sysfs_move_dir_ns(struct kobject *k, struct kobject *new_parent, const void *ns);
int rust_ko_uevent(struct kobject *k, int action);
int rust_ko_uevent_env(struct kobject *k, int action, char **envp);
void rust_ko_root_ownership(kuid_t *uid, kgid_t *gid);
gfp_t rust_ko_gfp_kernel(void);
char *rust_ko_kzalloc(size_t size, gfp_t gfp);
void rust_ko_kfree(const void *p);
void rust_ko_kfree_const(const char *p);
const char *rust_ko_kstrdup_const(const char *s);
char *rust_ko_devpath_old(const char *devpath);
void rust_ko_bug_on(bool cond);
void rust_ko_bug_null_fn(void);
void rust_ko_err_init_bad(struct kobject *kobj, int which);
void rust_ko_err_reinit(struct kobject *kobj);
void rust_ko_warn_empty_name(struct kobject *kobj);
void rust_ko_err_eexist(struct kobject *kobj);
void rust_ko_err_add(struct kobject *kobj, int error, struct kobject *parent);
void rust_ko_warn_uninit(struct kobject *kobj, bool get);
void rust_ko_err_no_ktype(void);

void rust_ko_ks_lock(struct kset *k) { spin_lock(&k->list_lock); }
void rust_ko_ks_unlock(struct kset *k) { spin_unlock(&k->list_lock); }
void rust_ko_ns_lock(void) { spin_lock(&kobj_ns_type_lock); }
void rust_ko_ns_unlock(void) { spin_unlock(&kobj_ns_type_lock); }
void rust_ko_list_add_tail(struct list_head *new, struct list_head *head) { list_add_tail(new, head); }
void rust_ko_list_del_init(struct list_head *entry) { list_del_init(entry); }
void rust_ko_init_list_head(struct list_head *l) { INIT_LIST_HEAD(l); }
void rust_ko_kref_init(struct kobject *k) { kref_init(&k->kref); }
void rust_ko_kref_get(struct kobject *k) { kref_get(&k->kref); }
bool rust_ko_kref_get_unless_zero(struct kobject *k) { return kref_get_unless_zero(&k->kref); }
void rust_ko_kref_put(struct kobject *k) { kref_put(&k->kref, kobject_release); }
void rust_ko_init_state(struct kobject *k)
{
	k->state_in_sysfs = 0;
	k->state_add_uevent_sent = 0;
	k->state_remove_uevent_sent = 0;
	k->state_initialized = 1;
}
bool rust_ko_get_initialized(const struct kobject *k) { return k->state_initialized; }
bool rust_ko_get_in_sysfs(const struct kobject *k) { return k->state_in_sysfs; }
void rust_ko_set_in_sysfs(struct kobject *k, bool v) { k->state_in_sysfs = v; }
bool rust_ko_get_add_sent(const struct kobject *k) { return k->state_add_uevent_sent; }
bool rust_ko_get_remove_sent(const struct kobject *k) { return k->state_remove_uevent_sent; }
int rust_ko_sysfs_create_dir_ns(struct kobject *k, const void *ns) { return sysfs_create_dir_ns(k, ns); }
int rust_ko_sysfs_create_groups(struct kobject *k, const struct attribute_group **groups) { return sysfs_create_groups(k, groups); }
void rust_ko_sysfs_remove_groups(struct kobject *k, const struct attribute_group **groups) { sysfs_remove_groups(k, groups); }
void rust_ko_sysfs_remove_dir(struct kobject *k) { sysfs_remove_dir(k); }
void rust_ko_sysfs_get(struct kobject *k) { sysfs_get(k->sd); }
void rust_ko_sysfs_put(struct kernfs_node *sd) { sysfs_put(sd); }
void rust_ko_sysfs_enable_ns(struct kobject *k) { sysfs_enable_ns(k->sd); }
int rust_ko_sysfs_rename_dir_ns(struct kobject *k, const char *new_name, const void *ns) { return sysfs_rename_dir_ns(k, new_name, ns); }
int rust_ko_sysfs_move_dir_ns(struct kobject *k, struct kobject *new_parent, const void *ns) { return sysfs_move_dir_ns(k, new_parent, ns); }
int rust_ko_uevent(struct kobject *k, int action) { return kobject_uevent(k, action); }
int rust_ko_uevent_env(struct kobject *k, int action, char **envp) { return kobject_uevent_env(k, action, envp); }
void rust_ko_root_ownership(kuid_t *uid, kgid_t *gid)
{
	*uid = GLOBAL_ROOT_UID;
	*gid = GLOBAL_ROOT_GID;
}
gfp_t rust_ko_gfp_kernel(void) { return GFP_KERNEL; }
char *rust_ko_kzalloc(size_t size, gfp_t gfp) { return kzalloc(size, gfp); }
void rust_ko_kfree(const void *p) { kfree(p); }
void rust_ko_kfree_const(const char *p) { kfree_const(p); }
const char *rust_ko_kstrdup_const(const char *s) { return kstrdup_const(s, GFP_KERNEL); }
char *rust_ko_devpath_old(const char *devpath)
{
	char *devpath_string = kmalloc(strlen(devpath) + 15, GFP_KERNEL);

	if (devpath_string)
		sprintf(devpath_string, "DEVPATH_OLD=%s", devpath);
	return devpath_string;
}
void rust_ko_bug_on(bool cond) { BUG_ON(cond); }
void rust_ko_bug_null_fn(void) { BUG(); }
void rust_ko_err_init_bad(struct kobject *kobj, int which)
{
	pr_err("kobject (%p): %s\n", kobj, which ? "must have a ktype to be initialized properly!\n" : "invalid kobject pointer!");
	dump_stack_lvl(KERN_ERR);
}
void rust_ko_err_reinit(struct kobject *kobj)
{
	pr_err("kobject (%p): tried to init an initialized object, something is seriously wrong.\n", kobj);
	dump_stack_lvl(KERN_ERR);
}
void rust_ko_warn_empty_name(struct kobject *kobj) { WARN(1, "kobject: (%p): attempted to be registered with empty name!\n", kobj); }
void rust_ko_err_eexist(struct kobject *kobj)
{
	pr_err("%s failed for %s with -EEXIST, don't try to register things with the same name in the same directory.\n", "kobject_add_internal",
	       kobject_name(kobj));
}
void rust_ko_err_add(struct kobject *kobj, int error, struct kobject *parent)
{
	pr_err("%s failed for %s (error: %d parent: %s)\n", "kobject_add_internal", kobject_name(kobj), error, parent ? kobject_name(parent) : "'none'");
}
void rust_ko_warn_uninit(struct kobject *kobj, bool get)
{
	if (get)
		WARN(1, KERN_WARNING "kobject: '%s' (%p): is not initialized, yet kobject_get() is being called.\n", kobject_name(kobj), kobj);
	else
		WARN(1, KERN_WARNING "kobject: '%s' (%p): is not initialized, yet kobject_put() is being called.\n", kobject_name(kobj), kobj);
}
void rust_ko_err_no_ktype(void) { pr_err("must have a ktype to be initialized properly!\n"); }

const void *kobject_namespace(const struct kobject *kobj) { return rust_kobject_namespace(kobj); }
void kobject_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid) { rust_kobject_get_ownership(kobj, uid, gid); }
char *kobject_get_path(const struct kobject *kobj, gfp_t gfp_mask) { return rust_kobject_get_path(kobj, gfp_mask); }
EXPORT_SYMBOL_GPL(kobject_get_path);
void kobject_init(struct kobject *kobj, const struct kobj_type *ktype) { rust_kobject_init(kobj, ktype); }
EXPORT_SYMBOL(kobject_init);
int kobject_rename(struct kobject *kobj, const char *new_name) { return rust_kobject_rename(kobj, new_name); }
EXPORT_SYMBOL_GPL(kobject_rename);
int kobject_move(struct kobject *kobj, struct kobject *new_parent) { return rust_kobject_move(kobj, new_parent); }
EXPORT_SYMBOL_GPL(kobject_move);
void kobject_del(struct kobject *kobj) { rust_kobject_del(kobj); }
EXPORT_SYMBOL(kobject_del);
struct kobject *kobject_get(struct kobject *kobj) { return rust_kobject_get(kobj); }
EXPORT_SYMBOL(kobject_get);
struct kobject * __must_check kobject_get_unless_zero(struct kobject *kobj) { return rust_kobject_get_unless_zero(kobj); }
EXPORT_SYMBOL(kobject_get_unless_zero);
void kobject_put(struct kobject *kobj) { rust_kobject_put(kobj); }
EXPORT_SYMBOL(kobject_put);
int kset_register(struct kset *k) { return rust_kset_register(k); }
EXPORT_SYMBOL(kset_register);
void kset_unregister(struct kset *k) { rust_kset_unregister(k); }
EXPORT_SYMBOL(kset_unregister);
struct kobject *kset_find_obj(struct kset *kset, const char *name) { return rust_kset_find_obj(kset, name); }
EXPORT_SYMBOL_GPL(kset_find_obj);
int kobj_ns_type_register(const struct kobj_ns_type_operations *ops) { return rust_kobj_ns_type_register(ops); }
int kobj_ns_type_registered(enum kobj_ns_type type) { return rust_kobj_ns_type_registered(type); }
const struct kobj_ns_type_operations *kobj_child_ns_ops(const struct kobject *parent) { return rust_kobj_child_ns_ops(parent); }
const struct kobj_ns_type_operations *kobj_ns_ops(const struct kobject *kobj) { return rust_kobj_ns_ops(kobj); }
bool kobj_ns_current_may_mount(enum kobj_ns_type type) { return rust_kobj_ns_current_may_mount(type); }
void *kobj_ns_grab_current(enum kobj_ns_type type) { return rust_kobj_ns_grab_current(type); }
EXPORT_SYMBOL_GPL(kobj_ns_grab_current);
void kobj_ns_drop(enum kobj_ns_type type, void *ns) { rust_kobj_ns_drop(type, ns); }
EXPORT_SYMBOL_GPL(kobj_ns_drop);

/**
 * kobject_set_name_vargs() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 * @vargs: vargs to format the string.
 */
int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs)
{
	const char *s;

	if (kobj->name && !fmt)
		return 0;

	s = kvasprintf_const(GFP_KERNEL, fmt, vargs);
	if (!s)
		return -ENOMEM;

	/*
	 * ewww... some of these buggers have '/' in the name ... If
	 * that's the case, we need to make sure we have an actual
	 * allocated copy to modify, since kvasprintf_const may have
	 * returned something from .rodata.
	 */
	if (strchr(s, '/')) {
		char *t;

		t = kstrdup(s, GFP_KERNEL);
		kfree_const(s);
		if (!t)
			return -ENOMEM;
		s = strreplace(t, '/', '!');
	}
	kfree_const(kobj->name);
	kobj->name = s;

	return 0;
}

/**
 * kobject_set_name() - Set the name of a kobject.
 * @kobj: struct kobject to set the name of
 * @fmt: format string used to build the name
 *
 * This sets the name of the kobject.  If you have already added the
 * kobject to the system, you must call kobject_rename() in order to
 * change the name of the kobject.
 */
int kobject_set_name(struct kobject *kobj, const char *fmt, ...)
{
	va_list vargs;
	int retval;

	va_start(vargs, fmt);
	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	va_end(vargs);

	return retval;
}
EXPORT_SYMBOL(kobject_set_name);

static __printf(3, 0) int kobject_add_varg(struct kobject *kobj,
					   struct kobject *parent,
					   const char *fmt, va_list vargs)
{
	int retval;

	retval = kobject_set_name_vargs(kobj, fmt, vargs);
	if (retval) {
		pr_err("can not set name properly!\n");
		return retval;
	}
	kobj->parent = parent;
	return rust_kobject_add_internal(kobj);
}

/**
 * kobject_add() - The main kobject add function.
 * @kobj: the kobject to add
 * @parent: pointer to the parent of the kobject.
 * @fmt: format to name the kobject with.
 *
 * The kobject name is set and added to the kobject hierarchy in this
 * function.
 *
 * If @parent is set, then the parent of the @kobj will be set to it.
 * If @parent is NULL, then the parent of the @kobj will be set to the
 * kobject associated with the kset assigned to this kobject.  If no kset
 * is assigned to the kobject, then the kobject will be located in the
 * root of the sysfs tree.
 *
 * Note, no "add" uevent will be created with this call, the caller should set
 * up all of the necessary sysfs files for the object and then call
 * kobject_uevent() with the UEVENT_ADD parameter to ensure that
 * userspace is properly notified of this kobject's creation.
 *
 * Return: If this function returns an error, kobject_put() must be
 *         called to properly clean up the memory associated with the
 *         object.  Under no instance should the kobject that is passed
 *         to this function be directly freed with a call to kfree(),
 *         that can leak memory.
 *
 *         If this function returns success, kobject_put() must also be called
 *         in order to properly clean up the memory associated with the object.
 *
 *         In short, once this function is called, kobject_put() MUST be called
 *         when the use of the object is finished in order to properly free
 *         everything.
 */
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...)
{
	va_list args;
	int retval;

	if (!kobj)
		return -EINVAL;

	if (!kobj->state_initialized) {
		pr_err("kobject '%s' (%p): tried to add an uninitialized object, something is seriously wrong.\n",
		       kobject_name(kobj), kobj);
		dump_stack_lvl(KERN_ERR);
		return -EINVAL;
	}
	va_start(args, fmt);
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
EXPORT_SYMBOL(kobject_add);

/**
 * kobject_init_and_add() - Initialize a kobject structure and add it to
 *                          the kobject hierarchy.
 * @kobj: pointer to the kobject to initialize
 * @ktype: pointer to the ktype for this kobject.
 * @parent: pointer to the parent of this kobject.
 * @fmt: the name of the kobject.
 *
 * This function combines the call to kobject_init() and kobject_add().
 *
 * If this function returns an error, kobject_put() must be called to
 * properly clean up the memory associated with the object.  This is the
 * same type of error handling after a call to kobject_add() and kobject
 * lifetime rules are the same here.
 */
int kobject_init_and_add(struct kobject *kobj, const struct kobj_type *ktype,
			 struct kobject *parent, const char *fmt, ...)
{
	va_list args;
	int retval;

	kobject_init(kobj, ktype);

	va_start(args, fmt);
	retval = kobject_add_varg(kobj, parent, fmt, args);
	va_end(args);

	return retval;
}
EXPORT_SYMBOL_GPL(kobject_init_and_add);

static void dynamic_kobj_release(struct kobject *kobj)
{
	pr_debug("(%p): %s\n", kobj, __func__);
	kfree(kobj);
}

static const struct kobj_type dynamic_kobj_ktype = {
	.release	= dynamic_kobj_release,
	.sysfs_ops	= &kobj_sysfs_ops,
};

/**
 * kobject_create() - Create a struct kobject dynamically.
 *
 * This function creates a kobject structure dynamically and sets it up
 * to be a "dynamic" kobject with a default release function set up.
 *
 * If the kobject was not able to be created, NULL will be returned.
 * The kobject structure returned from here must be cleaned up with a
 * call to kobject_put() and not kfree(), as kobject_init() has
 * already been called on this structure.
 */
static struct kobject *kobject_create(void)
{
	struct kobject *kobj;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return NULL;

	kobject_init(kobj, &dynamic_kobj_ktype);
	return kobj;
}

/**
 * kobject_create_and_add() - Create a struct kobject dynamically and
 *                            register it with sysfs.
 * @name: the name for the kobject
 * @parent: the parent kobject of this kobject, if any.
 *
 * This function creates a kobject structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kobject_put() and the structure will be dynamically freed when
 * it is no longer being used.
 *
 * If the kobject was not able to be created, NULL will be returned.
 */
struct kobject *kobject_create_and_add(const char *name, struct kobject *parent)
{
	struct kobject *kobj;
	int retval;

	kobj = kobject_create();
	if (!kobj)
		return NULL;

	retval = kobject_add(kobj, parent, "%s", name);
	if (retval) {
		pr_warn("%s: kobject_add error: %d\n", __func__, retval);
		kobject_put(kobj);
		kobj = NULL;
	}
	return kobj;
}
EXPORT_SYMBOL_GPL(kobject_create_and_add);

/**
 * kset_init() - Initialize a kset for use.
 * @k: kset
 */
void kset_init(struct kset *k)
{
	rust_kobject_init_internal(&k->kobj);
	INIT_LIST_HEAD(&k->list);
	spin_lock_init(&k->list_lock);
}

/* default kobject attribute operations */
static ssize_t kobj_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
	return ret;
}

static ssize_t kobj_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
	return ret;
}

const struct sysfs_ops kobj_sysfs_ops = {
	.show	= kobj_attr_show,
	.store	= kobj_attr_store,
};
EXPORT_SYMBOL_GPL(kobj_sysfs_ops);

static void kset_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	pr_debug("'%s' (%p): %s\n",
		 kobject_name(kobj), kobj, __func__);
	kfree(kset);
}

static void kset_get_ownership(const struct kobject *kobj, kuid_t *uid, kgid_t *gid)
{
	if (kobj->parent)
		kobject_get_ownership(kobj->parent, uid, gid);
}

static const struct kobj_type kset_ktype = {
	.sysfs_ops	= &kobj_sysfs_ops,
	.release	= kset_release,
	.get_ownership	= kset_get_ownership,
};

/**
 * kset_create() - Create a struct kset dynamically.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically.  This structure can
 * then be registered with the system and show up in sysfs with a call to
 * kset_register().  When you are finished with this structure, if
 * kset_register() has been called, call kset_unregister() and the
 * structure will be dynamically freed when it is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
static struct kset *kset_create(const char *name,
				const struct kset_uevent_ops *uevent_ops,
				struct kobject *parent_kobj)
{
	struct kset *kset;
	int retval;

	kset = kzalloc(sizeof(*kset), GFP_KERNEL);
	if (!kset)
		return NULL;
	retval = kobject_set_name(&kset->kobj, "%s", name);
	if (retval) {
		kfree(kset);
		return NULL;
	}
	kset->uevent_ops = uevent_ops;
	kset->kobj.parent = parent_kobj;

	/*
	 * The kobject of this kset will have a type of kset_ktype and belong to
	 * no kset itself.  That way we can properly free it when it is
	 * finished being used.
	 */
	kset->kobj.ktype = &kset_ktype;
	kset->kobj.kset = NULL;

	return kset;
}

/**
 * kset_create_and_add() - Create a struct kset dynamically and add it to sysfs.
 *
 * @name: the name for the kset
 * @uevent_ops: a struct kset_uevent_ops for the kset
 * @parent_kobj: the parent kobject of this kset, if any.
 *
 * This function creates a kset structure dynamically and registers it
 * with sysfs.  When you are finished with this structure, call
 * kset_unregister() and the structure will be dynamically freed when it
 * is no longer being used.
 *
 * If the kset was not able to be created, NULL will be returned.
 */
struct kset *kset_create_and_add(const char *name,
				 const struct kset_uevent_ops *uevent_ops,
				 struct kobject *parent_kobj)
{
	struct kset *kset;
	int error;

	kset = kset_create(name, uevent_ops, parent_kobj);
	if (!kset)
		return NULL;
	error = kset_register(kset);
	if (error) {
		kfree(kset);
		return NULL;
	}
	return kset;
}
EXPORT_SYMBOL_GPL(kset_create_and_add);

#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
static void kobject_delayed_cleanup(struct work_struct *work)
{
	rust_kobject_cleanup(container_of(to_delayed_work(work),
				     struct kobject, release));
}
#endif

static void kobject_release(struct kref *kref)
{
	struct kobject *kobj = container_of(kref, struct kobject, kref);
#ifdef CONFIG_DEBUG_KOBJECT_RELEASE
	unsigned long delay = HZ + HZ * get_random_u32_below(4);
	pr_info("'%s' (%p): %s, parent %p (delayed %ld)\n",
		kobject_name(kobj), kobj, __func__, kobj->parent, delay);
	INIT_DELAYED_WORK(&kobj->release, kobject_delayed_cleanup);

	schedule_delayed_work(&kobj->release, delay);
#else
	rust_kobject_cleanup(kobj);
#endif
}
