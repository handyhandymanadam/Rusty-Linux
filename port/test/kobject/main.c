/* kobject differential: the same op stream drives pristine lib/kobject.c (ARM_REF) or kobject_glue.c over kobject_rs.rs (ARM_RS) through the public API.
 * Pool: 8 static kobjects, 3 static ksets, up to 6 dynamic kobjects and 3 dynamic ksets (kobject_create_and_add / kset_create_and_add). The sysfs and uevent layers are stubs that
 * keep a model of "directories" (sibling-name conflicts give -EEXIST) and take injected failures; the allocator fails on request. Ops: init, add, init_and_add, set_name, del, get,
 * put, get_unless_zero, rename, move, get_path, namespace, kset_register / unregister / find_obj, create_and_add, namespace-type registry calls. After every op the whole pool
 * (refcount, bits, name, parent, kset, list membership), the ksets' lists, and the counters (allocations outstanding, warnings, sd gets/puts, lock balance) are printed.
 * usage: t SHARD (env KO_N ops, KO_PROVE=1 prints a poisoned line) */
#include <stdint.h>
#include <ctype.h>
#include <linux/kobject.h>

long lock_ops, lock_depth; int warn_count;
static long allocs_out, alloc_calls, alloc_bytes; static struct kobject *hook_target; static int hook_k; static long fail_alloc_in = -1;
static int inj_create, inj_groups, inj_rename, inj_move;
static long sd_made, sd_gets, sd_puts, ev_count;
#include SRC

/* ---- log with pointers scrubbed ---- */
void klog(const char *tag, const char *fmt, ...)
{
	char buf[1024], out[1100]; va_list ap; int o = 0;
	va_start(ap, fmt); vsnprintf(buf, sizeof buf, fmt, ap); va_end(ap);
	for (char *p = buf; *p && o < 1090; ) {
		if (p[0] == '0' && p[1] == 'x' && isxdigit((unsigned char)p[2])) { p += 2; while (isxdigit((unsigned char)*p)) p++; o += sprintf(out + o, "PTR"); }
		else out[o++] = *p++;
	}
	out[o] = 0;
	printf("  LOG %s: %s%s", tag, out, (o && out[o - 1] == '\n') ? "" : "\n");
}

/* ---- allocator ---- */
static int alloc_fails(void) { alloc_calls++; if (fail_alloc_in == 0) { fail_alloc_in = -1; return 1; } if (fail_alloc_in > 0) fail_alloc_in--; return 0; }
static void *dynk[6], *dyns[3];
void *kmalloc(size_t n, gfp_t g) { (void)g; if (alloc_fails()) return NULL; allocs_out++; alloc_bytes += n; return malloc(n); }
void *kzalloc(size_t n, gfp_t g)
{
	(void)g;
	if (hook_target) { /* the name of the object whose path is being built grows between get_kobj_path_length() and fill_kobj_path() */
		char *old = (char *)hook_target->name, *nn = malloc(strlen(old) + 1 + hook_k);
		strcpy(nn, old); memset(nn + strlen(old), 'Z', hook_k); nn[strlen(old) + hook_k] = 0; free(old); hook_target->name = nn; hook_target = NULL;
	}
	if (alloc_fails()) return NULL; allocs_out++; alloc_bytes += n; return calloc(1, n);
}
void kfree(const void *p)
{
	if (!p) return;
	for (int i = 0; i < 6; i++) if (dynk[i] == p) dynk[i] = NULL;
	for (int i = 0; i < 3; i++) if (dyns[i] == p) dyns[i] = NULL;
	allocs_out--; free((void *)p);
}
char *kstrdup(const char *s, gfp_t g) { (void)g; if (!s) return NULL; if (alloc_fails()) return NULL; allocs_out++; alloc_bytes += strlen(s) + 1; return strdup(s); }
const char *kstrdup_const(const char *s, gfp_t g) { return kstrdup(s, g); }
void kfree_const(const void *p) { kfree(p); }
const char *kvasprintf_const(gfp_t g, const char *fmt, va_list ap)
{
	char *r; (void)g; if (alloc_fails()) return NULL; if (vasprintf(&r, fmt, ap) < 0) return NULL; allocs_out++; alloc_bytes += strlen(r) + 1; return r;
}
char *strreplace(char *str, char old, char new) { for (char *s = str; *s; ++s) if (*s == old) *s = new; return str; }

/* ---- kobject_uevent / sysfs model ---- */
extern struct kobject *all_kobj[]; extern int n_all;
static struct kobject *allk[40]; static int nallk;
struct kernfs_node { int id; };
static struct kernfs_node sdpool[100000];
static int idx_of(const struct kobject *k);
static const char *nm(const struct kobject *k) { return k && k->name ? k->name : "-"; }
int kobject_uevent(struct kobject *kobj, enum kobject_action action)
{
	ev_count++; printf("  EV %d on %d\n", action, idx_of(kobj));
	if (action == KOBJ_ADD) kobj->state_add_uevent_sent = 1; else if (action == KOBJ_REMOVE) kobj->state_remove_uevent_sent = 1;
	return 0;
}
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action, char *envp[])
{
	ev_count++; printf("  EVENV %d on %d [%s]\n", action, idx_of(kobj), envp[0]); return 0;
}
static const struct kobject *sibling(const struct kobject *self, const struct kobject *parent, const char *name)
{
	for (int i = 0; i < nallk; i++) {
		struct kobject *o = allk[i];
		if (!o || o == self || !o->state_in_sysfs || o->parent != parent || !o->name) continue;
		if (!strcmp(o->name, name)) return o;
	}
	return NULL;
}
int sysfs_create_dir_ns(struct kobject *kobj, const void *ns)
{
	printf("  SYSFS create %s ns=%d\n", nm(kobj), ns != NULL);
	if (inj_create) { inj_create = 0; return -ENOMEM; }
	if (sibling(kobj, kobj->parent, kobj->name)) return -EEXIST;
	kobj->sd = &sdpool[sd_made % 100000]; sd_made++; sd_gets++; /* kernfs_create_dir returns a referenced node */
	return 0;
}
int sysfs_create_groups(struct kobject *kobj, const struct attribute_group **groups)
{
	printf("  SYSFS groups %s %d\n", nm(kobj), groups != NULL);
	if (inj_groups) { inj_groups = 0; return -EINVAL; }
	return 0;
}
void sysfs_remove_groups(struct kobject *kobj, const struct attribute_group **groups) { printf("  SYSFS rmgroups %s %d\n", nm(kobj), groups != NULL); }
void sysfs_remove_dir(struct kobject *kobj) { printf("  SYSFS rmdir %s sd=%d\n", nm(kobj), kobj->sd != NULL); kobj->sd = NULL; }
void sysfs_get(struct kernfs_node *sd) { sd_gets++; (void)sd; }
void sysfs_put(struct kernfs_node *sd) { sd_puts++; (void)sd; }
void sysfs_enable_ns(struct kernfs_node *sd) { printf("  SYSFS enable_ns %d\n", sd != NULL); }
int sysfs_rename_dir_ns(struct kobject *kobj, const char *new_name, const void *new_ns)
{
	printf("  SYSFS rename %s -> %s ns=%d\n", nm(kobj), new_name, new_ns != NULL);
	if (inj_rename) { inj_rename = 0; return -ENOMEM; }
	if (sibling(kobj, kobj->parent, new_name)) return -EEXIST;
	return 0;
}
int sysfs_move_dir_ns(struct kobject *kobj, struct kobject *np, const void *new_ns)
{
	printf("  SYSFS move %s -> %d ns=%d\n", nm(kobj), idx_of(np), new_ns != NULL);
	if (inj_move) { inj_move = 0; return -ENOMEM; }
	if (sibling(kobj, np, kobj->name)) return -EEXIST;
	return 0;
}

/* ---- pool ---- */
#define NK 8
#define NS 3
static struct kobject sk[NK]; static struct kset ss[NS];
#define dk ((struct kobject **)dynk)
#define ds ((struct kset **)dyns)
static int idx_of(const struct kobject *k)
{
	if (!k) return -1;
	for (int i = 0; i < NK; i++) if (k == &sk[i]) return i;
	for (int i = 0; i < NS; i++) if (k == &ss[i].kobj) return 10 + i;
	for (int i = 0; i < 6; i++) if (k == dk[i]) return 20 + i;
	for (int i = 0; i < 3; i++) if (ds[i] && k == &ds[i]->kobj) return 30 + i;
	return 99;
}
static struct kobject *at(int i)
{
	if (i < NK) return &sk[i];
	if (i < NK + NS) return &ss[i - NK].kobj;
	if (i < NK + NS + 6) return dk[i - NK - NS];
	return ds[i - NK - NS - 6] ? &ds[i - NK - NS - 6]->kobj : NULL;
}
static void rebuild_all(void)
{
	nallk = 0;
	for (int i = 0; i < NK; i++) allk[nallk++] = &sk[i];
	for (int i = 0; i < NS; i++) allk[nallk++] = &ss[i].kobj;
	for (int i = 0; i < 6; i++) if (dk[i]) allk[nallk++] = dk[i];
	for (int i = 0; i < 3; i++) if (ds[i]) allk[nallk++] = &ds[i]->kobj;
}
static void sync_dyn(void) { rebuild_all(); }

static int released[64]; static long rel_count;
static void rel_plain(struct kobject *k)
{
	int i = idx_of(k); rel_count++; printf("  RELEASE %d\n", i);
	if (i >= 10 && i < 10 + NS) { struct kset *s = container_of(k, struct kset, kobj); memset(s, 0, sizeof *s); } else memset(k, 0, sizeof *k);
}
static int groups_dummy;
static const struct attribute_group **GROUPS = (const struct attribute_group **)&groups_dummy;
static bool ns_registered;
static bool ns_may(void) { printf("  NS may_mount\n"); return false; }
static int ns_token; static int ns_drops;
static void *ns_grab(void) { printf("  NS grab\n"); return &ns_token; }
static void ns_drop(void *p) { ns_drops++; printf("  NS drop %d\n", p == &ns_token); }
static const struct kobj_ns_type_operations ops_net = { KOBJ_NS_TYPE_NET, ns_may, ns_grab, NULL, NULL, ns_drop };
static const struct kobj_ns_type_operations ops_net_nodrop = { KOBJ_NS_TYPE_NET, ns_may, ns_grab, NULL, NULL, NULL };
static const struct kobj_ns_type_operations ops_none = { KOBJ_NS_TYPE_NONE, ns_may, ns_grab, NULL, NULL, ns_drop };
static const struct kobj_ns_type_operations ops_bad = { (enum kobj_ns_type)7, ns_may, ns_grab, NULL, NULL, ns_drop };
static const struct kobj_ns_type_operations *ns_child(const struct kobject *k) { (void)k; return &ops_net; }
static const void *ns_ns(const struct kobject *k) { (void)k; return &ns_token; }
static void ownf(const struct kobject *k, kuid_t *u, kgid_t *g) { u->v = 1000 + idx_of(k); g->v = 2000 + idx_of(k); }
static const void *ns_ns(const struct kobject *k);
static const struct kobj_type kt_plain = { .release = rel_plain, .namespace = ns_ns };
static const struct kobj_type kt_groups = { .release = rel_plain, .default_groups = (const struct attribute_group **)&groups_dummy, .namespace = ns_ns };
static const struct kobj_type kt_ns = { .release = rel_plain, .child_ns_type = ns_child, .namespace = ns_ns, .get_ownership = ownf };
static const struct kobj_type kt_norel = { .release = NULL, .namespace = ns_ns };
static const struct kobj_type *KT[] = { &kt_plain, &kt_groups, &kt_norel, &kt_ns };

static const char *NAMES[] = { "a", "b", "c", "d", "x/y", "", "a/b/c", "this-is-a-fairly-long-kobject-name-0123456789", "caf\xc3\xa9" };
#define NNAMES 9

static bool alive(const struct kobject *k) { return k && k->state_initialized && k->kref.refcount.refs > 0; }
static bool good_parent(const struct kobject *k) { return alive(k) && k->state_in_sysfs; }
static bool is_anc(const struct kobject *a, const struct kobject *b) { for (int i = 0; b && i < 60; i++, b = b->parent) if (a == b) return true; return false; }
static bool ns_ok(const struct kobj_type *child, const struct kobject *p) { return !p || !p->ktype || !p->ktype->child_ns_type || (child && child->namespace); }
static bool idle(const struct kobject *k) { return alive(k) && !k->state_in_sysfs && k->entry.next == &k->entry; }
static int own[NK + NS + 6 + 3]; /* references the test itself holds, per pool slot: it may only put what it owns */
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }

static void show_kobj(int i, struct kobject *k)
{
	if (!k) { printf(" [%d:-]", i); return; }
	if (!k->state_initialized && !k->name && !k->kref.refcount.refs) { printf(" [%d:.]", i); return; }
	if (k->state_initialized && k->kref.refcount.refs <= 0) { printf(" [%d:dead r%d]", i, k->kref.refcount.refs); return; }
	printf(" [%d:%s r%d i%d s%d a%d d%d p%d k%d t%d sd%d e%d]", i, nm(k), k->kref.refcount.refs, k->state_initialized, k->state_in_sysfs, k->state_add_uevent_sent, k->state_remove_uevent_sent,
	       idx_of(k->parent), idx_of(k->kset ? &k->kset->kobj : NULL), k->ktype == &kt_plain ? 0 : k->ktype == &kt_groups ? 1 : k->ktype == &kt_ns ? 2 : k->ktype ? 3 : -1, k->sd != NULL,
	       k->entry.next == &k->entry ? 0 : 1);
}
static void try_dup(void)
{
	struct kset *cand = &ss[rnd(NS)]; struct kobject *m1 = &sk[rnd(NK)], *m2 = &sk[rnd(NK)], *pp = rnd(2) ? &ss[rnd(NS)].kobj : &sk[rnd(NK)]; int r, r2;
	if (m1 != m2 && pp != m1 && pp != m2 && pp != &cand->kobj && idle(m1) && idle(m2) && good_parent(&cand->kobj) && good_parent(pp) && !is_anc(m1, &cand->kobj) && !is_anc(m2, &cand->kobj) && !is_anc(m2, pp) &&
	    ns_ok(m1->ktype, &cand->kobj) && ns_ok(m2->ktype, &cand->kobj) && ns_ok(m2->ktype, pp)) {
		m1->kset = cand; r = kobject_add(m1, NULL, "%s", "dup"); m2->kset = cand; r2 = kobject_add(m2, pp, "%s", "dup"); printf("dup members -> %d %d\n", r, r2);
	} else printf("skip\n");
}
static void state(void)
{
	sync_dyn();
	printf("  S bytes=%ld warn=%d allocs=%ld calls=%ld rel=%ld ev=%ld sd=%ld/%ld/%ld lock=%ld/%ld ns=%d drops=%d\n", alloc_bytes, warn_count, allocs_out, alloc_calls, rel_count, ev_count, sd_made, sd_gets, sd_puts, lock_ops, lock_depth,
	       ns_registered, ns_drops);
	printf("  K");
	for (int i = 0; i < NK; i++) show_kobj(i, &sk[i]);
	for (int i = 0; i < NS; i++) show_kobj(10 + i, &ss[i].kobj);
	for (int i = 0; i < 6; i++) show_kobj(20 + i, dk[i]);
	for (int i = 0; i < 3; i++) show_kobj(30 + i, ds[i] ? &ds[i]->kobj : NULL);
	printf("\n");
	for (int i = 0; i < NS + 3; i++) {
		struct kset *s = i < NS ? &ss[i] : ds[i - NS]; struct kobject *k;
		if (!s || !s->list.next) continue;
		printf("  L%d:", i < NS ? 10 + i : 30 + i - NS);
		for (struct list_head *p = s->list.next; p != &s->list && p; p = p->next) { k = container_of(p, struct kobject, entry); printf(" %d", idx_of(k)); }
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("KO_N") ? atol(getenv("KO_N")) : 20000; int prove = getenv("KO_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	rebuild_all();
	for (int i = 0; i < NS; i++) { /* the static ksets start registered, so membership is exercised from the first op */
		ss[i].kobj.ktype = &kt_plain; kobject_set_name(&ss[i].kobj, "ks%d", i); printf("boot kset_register %d -> %d\n", i, kset_register(&ss[i])); own[NK + i] = 1;
	}
	state();
	for (long s = 0; s < n; s++) {
		unsigned op = rnd(100); int a = rnd(10) < 6 ? rnd(NK + NS) : rnd(NK + NS + 6 + 3), b = rnd(10) < 6 ? rnd(NK + NS) : rnd(NK + NS + 6 + 3), nmi = rnd(NNAMES);
		struct kobject *ka = at(a), *kb = at(b), *par = rnd(4) ? kb : NULL; int r;
		if (rnd(40) == 0) { switch (rnd(4)) { case 0: inj_create = 1; break; case 1: inj_groups = 1; break; case 2: inj_rename = 1; break; default: inj_move = 1; } }
		if (rnd(60) == 0) fail_alloc_in = rnd(4);
		printf("%ld ", s);
		if (op < 10) {
			const struct kobj_type *kt = KT[rnd(ns_registered ? 4 : 3)];
			if (ka && a < NK && (!alive(ka) || (rnd(6) == 0 && idle(ka) && ka->kref.refcount.refs == 1))) { if (!alive(ka)) memset(ka, 0, sizeof *ka); kobject_init(ka, rnd(10) ? kt : NULL); own[a] = ka->state_initialized; printf("init %d\n", a); }
			else if (a >= NK && a < NK + NS && ka && !ka->state_initialized) { ss[a - NK].kobj.ktype = rnd(8) ? kt : NULL; printf("kset_ktype %d\n", a); }
			else printf("skip\n");
		} else if (op < 22) {
			if (idle(ka) && a < NK && (!par || (good_parent(par) && !is_anc(ka, par) && ns_ok(ka->ktype, par)))) {
				struct kset *want = NULL;
				if (rnd(2) == 0) { struct kset *cand = &ss[rnd(NS)]; if (good_parent(&cand->kobj) && !is_anc(ka, &cand->kobj) && ns_ok(ka->ktype, &cand->kobj)) want = cand; }
				ka->kset = want;
				if (rnd(2)) { r = kobject_add(ka, par, "%s", NAMES[nmi]); printf("add %d parent %d name '%s' -> %d\n", a, b, NAMES[nmi], r); }
				else if (nmi == 4) { r = kobject_add(ka, par, "%s-%d", NAMES[nmi], (int)(s % 7)); printf("add-fmt %d parent %d -> %d\n", a, b, r); }
				else { r = kobject_add(ka, par, "n%d", (int)(s % 5)); printf("add-fmt %d parent %d -> %d\n", a, b, r); }
			} else printf("skip\n");
		} else if (op < 26) {
			if (ka && a < NK && !alive(ka) && (!par || good_parent(par))) { const struct kobj_type *kt = KT[rnd(ns_registered ? 4 : 3)]; memset(ka, 0, sizeof *ka); r = kobject_init_and_add(ka, kt, par, "%s", NAMES[nmi]); own[a] = ka->state_initialized; printf("init_and_add %d parent %d name '%s' -> %d\n", a, b, NAMES[nmi], r); }
			else printf("skip\n");
		} else if (op < 30) {
			if (alive(ka) && a < NK) { int nf = rnd(5) == 0 && ka->name; r = kobject_set_name(ka, nf ? NULL : "%s", NAMES[nmi]); printf("set_name %d '%s' nullfmt=%d -> %d\n", a, NAMES[nmi], nf, r); } else printf("skip\n");
		} else if (op < 38) {
			if (alive(ka) && ka->state_in_sysfs && !(a >= NK && a < NK + NS) && a < NK + NS + 6) { kobject_del(ka); printf("del %d\n", a); } else printf("skip\n");
		} else if (op < 46) {
			if (alive(ka)) { kobject_get(ka); own[a]++; printf("get %d\n", a); } else printf("skip\n");
		} else if (op < 58) {
			if (alive(ka) && own[a] > 0 && !(a >= NK && a < NK + NS && rnd(5))) { own[a]--; kobject_put(ka); printf("put %d\n", a); } else printf("skip\n");
		} else if (op < 62) {
			if (alive(ka)) { struct kobject *g = kobject_get_unless_zero(ka); if (g) own[a]++; printf("get_unless_zero %d -> %d\n", a, g != NULL); } else printf("skip\n");
		} else if (op < 67) {
			if (alive(ka) && ka->state_in_sysfs) { r = kobject_rename(ka, NAMES[nmi]); printf("rename %d '%s' -> %d\n", a, NAMES[nmi], r); } else printf("skip\n");
		} else if (op < 72) {
			struct kobject *np = par;
			if (alive(ka) && ka->state_in_sysfs && ka != np && (!np || (good_parent(np) && !is_anc(ka, np) && ns_ok(ka->ktype, np)))) { r = kobject_move(ka, np); printf("move %d to %d -> %d\n", a, b, r); } else printf("skip\n");
		} else if (op < 77) {
			if (alive(ka) && (ka->state_in_sysfs || !ka->parent)) { if (ka->state_in_sysfs && rnd(4) == 0) { hook_target = ka; hook_k = 1 + rnd(2); } char *p = kobject_get_path(ka, GFP_KERNEL); hook_target = NULL; printf("path %d -> %s\n", a, p ? p : "(null)"); kfree(p); } else printf("skip\n");
		} else if (op < 79) {
			if (alive(ka) && ka->state_in_sysfs && ka->ktype) { const void *ns = kobject_namespace(ka); kuid_t u = { 777 }; kgid_t g = { 777 }; kobject_get_ownership(ka, &u, &g); printf("namespace %d -> %d own %u/%u\n", a, ns != NULL, u.v, g.v); } else printf("skip\n");
		} else if (op < 83) {
			if (a >= NK && a < NK + NS) {
				struct kset *ks = &ss[a - NK];
				if (!ks->kobj.state_initialized && !ks->kobj.ktype && rnd(8)) ks->kobj.ktype = &kt_plain;
				if (alive(&ks->kobj) && !ks->kobj.state_in_sysfs) { if (own[a] > 0) own[a]--; kobject_put(&ks->kobj); printf("kset_put-failed %d\n", a); }
				else if (!ks->kobj.state_initialized && ks->kobj.ktype) {
					struct kobject *pp = par && good_parent(par) && !is_anc(&ks->kobj, par) && par->kset != ks ? par : NULL;
					ks->kobj.parent = pp;
					r = rnd(6) ? kobject_set_name(&ks->kobj, "ks%d-%d", a - NK, (int)(s % 3)) : kobject_set_name(&ks->kobj, "%s", NAMES[nmi]); r = r ? r : kset_register(ks); own[a] = ks->kobj.state_initialized; printf("kset_register %d '%s' -> %d\n", a, NAMES[nmi], r);
				} else if (alive(&ks->kobj) && ks->kobj.state_in_sysfs && own[a] > 0 && rnd(6) == 0) { own[a]--; kset_unregister(ks); printf("kset_unregister %d\n", a); }
				else if (!ks->kobj.state_initialized) { r = kset_register(ks); own[a] = ks->kobj.state_initialized; printf("kset_register-nokt %d -> %d\n", a, r); }
				else printf("skip\n");
			} else if (rnd(4) == 0) { r = kset_register(NULL); kset_unregister(NULL); printf("kset NULL -> %d\n", r); }
			else printf("skip\n");
		} else if (op < 90) {
			struct kset *ks = rnd(4) ? &ss[rnd(NS)] : ds[rnd(3)];
			if (ks && alive(&ks->kobj) && ks->kobj.state_in_sysfs) { const char *want = rnd(3) ? NAMES[nmi] : "dup"; struct list_head *p = ks->list.next; for (int skip = rnd(4); p != &ks->list && skip > 0; skip--) p = p->next;
				if (p != &ks->list && rnd(3)) want = container_of(p, struct kobject, entry)->name ? container_of(p, struct kobject, entry)->name : want;
				int nm_n = 0; for (struct list_head *q = ks->list.next; q != &ks->list; q = q->next) { const char *qn = container_of(q, struct kobject, entry)->name; if (qn && !strcmp(qn, want)) nm_n++; }
				struct kobject *f = kset_find_obj(ks, want); printf("find %d '%s' matches=%d -> %d\n", a, want, nm_n, idx_of(f)); if (f) kobject_put(f); } else printf("skip\n");
		} else if (op < 92) {
			int i = rnd(6);
			if (!dk[i] && (!par || (good_parent(par) && ns_ok(NULL, par)))) {
				struct kobject *k = kobject_create_and_add(NAMES[nmi], par);
				if (k) { dk[i] = k; own[NK + NS + i] = 1; }
				printf("create_and_add %d '%s' -> %d\n", i, NAMES[nmi], k != NULL);
				sync_dyn();
			} else printf("skip\n");
		} else if (op < 93) {
			int i = rnd(3);
			if (!ds[i] && (!par || (good_parent(par) && ns_ok(NULL, par)))) {
				struct kset *k = kset_create_and_add(NAMES[nmi], NULL, par);
				if (k) { ds[i] = k; own[NK + NS + 6 + i] = 1; }
				printf("kset_create_and_add %d '%s' -> %d\n", i, NAMES[nmi], k != NULL);
				sync_dyn();
			} else if (ds[i] && own[NK + NS + 6 + i] > 0) { own[NK + NS + 6 + i]--; kset_unregister(ds[i]); printf("kset_unregister dyn %d\n", i); sync_dyn(); } else printf("skip\n");
		} else if (op < 97) {
			if (rnd(3) == 0) { try_dup(); goto done_op; }
			struct kset *cand = &ss[rnd(NS)]; int j = rnd(NK); struct kobject *m = &sk[j];
			if (idle(m) && good_parent(&cand->kobj) && !is_anc(m, &cand->kobj) && ns_ok(m->ktype, &cand->kobj)) {
				m->kset = cand; { struct kobject *pp = &sk[rnd(NK)]; if (rnd(2) || pp == m || !good_parent(pp) || is_anc(m, pp) || !ns_ok(m->ktype, pp)) pp = NULL; const char *dn = cand->list.next != &cand->list && rnd(2) ? container_of(cand->list.next, struct kobject, entry)->name : NULL; r = dn ? kobject_add(m, pp, "%s", dn) : kobject_add(m, pp, "m%d", (int)rnd(3)); } printf("member add %d -> %d\n", j, r);
			} else printf("skip\n");
		} else {
			int w = rnd(16);
			switch (w) {
			case 0: r = kobj_ns_type_register(rnd(2) ? &ops_net : &ops_net_nodrop); if (r == 0) ns_registered = true; printf("ns_register net -> %d\n", r); break;
			case 1: printf("ns_register none -> %d\n", kobj_ns_type_register(&ops_none)); break;
			case 2: printf("ns_register bad -> %d\n", kobj_ns_type_register(&ops_bad)); break;
			case 3: printf("ns_registered %d %d %d %d\n", kobj_ns_type_registered(0), kobj_ns_type_registered(1), kobj_ns_type_registered(2), kobj_ns_type_registered((enum kobj_ns_type)-1)); break;
			case 4: printf("ns_may_mount %d %d %d\n", kobj_ns_current_may_mount(0), kobj_ns_current_may_mount(1), kobj_ns_current_may_mount(5)); break;
			case 5: printf("ns_grab %d %d\n", kobj_ns_grab_current(1) != NULL, kobj_ns_grab_current(0) != NULL); break;
			case 6: kobj_ns_drop(1, &ns_token); kobj_ns_drop(0, &ns_token); kobj_ns_drop(9, NULL); printf("ns_drop\n"); break;
			case 7: printf("child_ns_ops %d ns_ops %d\n", ka && alive(ka) && ka->ktype ? kobj_child_ns_ops(ka) != NULL : -1, ka && alive(ka) && ka->state_in_sysfs && ka->parent && ka->parent->ktype ? kobj_ns_ops(ka) != NULL : -1); break;
			case 8: printf("child_ns_ops NULL %d\n", kobj_child_ns_ops(NULL) != NULL); break;
			case 9: kset_unregister(NULL); printf("null kset %d\n", kset_register(NULL)); kobject_init(NULL, &kt_plain); kobject_del(NULL); kobject_put(NULL); printf("null init/del/put %p\n", (void *)kobject_get(NULL)); break;
			case 10: printf("null rename/move %d %d %d\n", kobject_rename(NULL, "x"), kobject_move(NULL, NULL), kobject_add(NULL, NULL, "%s", "x")); break;
			case 11: printf("null gunz %d\n", kobject_get_unless_zero(NULL) != NULL); break;
			case 12: {
				struct kobject *u = &sk[rnd(NK)];
				if (!alive(u) && !u->name) { memset(u, 0, sizeof *u); kobject_get(u); kobject_put(u); kobject_get(u); kobject_get_unless_zero(u); kobject_put(u); kobject_put(u); memset(u, 0, sizeof *u); printf("uninit get/put\n"); }
				else printf("skip\n");
				break;
			}
			case 14: try_dup(); break;
			default: { struct kset *k = &ss[rnd(NS)]; if (!k->kobj.state_initialized) { k->kobj.ktype = NULL; printf("kset_register no ktype -> %d\n", kset_register(k)); } else printf("skip\n"); break; }
			}
		}
		done_op:;
		if (prove && s == 20) printf("  POISON\n");
		state();
		if (lock_depth) { printf("LOCK LEAK\n"); return 1; }
	}
	/* drain: delete and drop everything so leaks show */
	for (int i = 0; i < NK + NS + 6 + 3; i++) {
		struct kobject *k = at(i);
		if (k && k->state_initialized && k->kref.refcount.refs > 0 && i < NK) { kobject_del(k); }
	}
	state();
	printf("final warn=%d allocs=%ld\n", warn_count, allocs_out);
	return 0;
}
