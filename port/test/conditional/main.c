/* SELinux conditional policy differential: the pristine conditional.c (ARM_REF) against conditional_rs.rs with the glue's wrappers (ARM_RS); avtab, hashtab and symtab are the pristine C in both. A policydb shim
 * with the same field offsets as the real one is set up with random booleans (read through cond_read_bool from crafted streams, some invalid), a conditional list read through cond_read_list from
 * crafted streams (valid ones with random expressions and rule lists, invalid operators / booleans / conflicting type rules / truncations), then evaluated after random boolean changes,
 * asked for access decisions and extended permissions, written, duplicated and destroyed, with allocation failures injected. Every result and the state it leaves are printed.   usage: t SHARD */
#include "refshim.h"
#include "avtab.h"
#include "policydb.h"
#include "conditional.h"
#include "services.h"
long fail_in, live_nodes, allocs, live, resched_count;
struct kmem_cache *avtab_node_cachep, *avtab_xperms_cachep, *hashtab_node_cachep;
int str_read(char **strp, int flags, struct policy_file *fp, u32 len)
{
	int rc; char *str;
	if ((len == 0) || (len == (u32)-1)) return -EINVAL;
	allocs++; if (fail_in > 0 && --fail_in == 0) return -ENOMEM;
	str = malloc(len + 1); live++;
	rc = next_entry(str, fp, len);
	if (rc) { free(str); live--; return rc; }
	str[len] = '\0'; *strp = str; return 0;
}
static int nx_decision, nx_drivers;
void services_compute_xperms_decision(struct extended_perms_decision *xpermd, struct avtab_node *node) { nx_decision++; printf("    xdecision %u,%u,%u,%x\n", node->key.source_type, node->key.target_type, node->key.target_class, node->key.specified); }
void services_compute_xperms_drivers(struct extended_perms *xperms, struct avtab_node *node) { nx_drivers++; printf("    xdrivers %u,%u,%u,%x\n", node->key.source_type, node->key.target_type, node->key.target_class, node->key.specified); }
#include SRCFILE
static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }
static void put32(unsigned char *p, u32 v) { memcpy(p, &v, 4); }
static void put16(unsigned char *p, u16 v) { memcpy(p, &v, 2); }
static const u16 specs[] = { AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY, AVTAB_TRANSITION, AVTAB_MEMBER, AVTAB_CHANGE, AVTAB_XPERMS_ALLOWED };

static void dumpav(struct avtab *a)
{
	u32 s; struct avtab_node *n;
	printf("  avtab nel=%u nslot=%u", a->nel, a->nslot);
	for (s = 0; s < a->nslot; s++) for (n = a->htable[s]; n; n = n->next) {
		printf(" (%u:%u,%u,%u,%x", s, n->key.source_type, n->key.target_type, n->key.target_class, n->key.specified);
		if (n->key.specified & AVTAB_XPERMS) printf(" x%u/%u.%x", n->datum.u.xperms->specified, n->datum.u.xperms->driver, n->datum.u.xperms->perms.p[0]); else printf(" %x", n->datum.u.data);
		printf(")");
	}
	printf("\n");
}
static void dumpbools(struct policydb *p)
{
	u32 s; struct hashtab_node *n;
	printf("  bools nprim=%u nel=%u:", p->p_bools.nprim, p->p_bools.table.nel);
	for (s = 0; s < p->p_bools.table.size; s++) for (n = p->p_bools.table.htable[s]; n; n = n->next) printf(" %s=%u/%d", (char *)n->key, ((struct cond_bool_datum *)n->datum)->value, ((struct cond_bool_datum *)n->datum)->state);
	printf(" names:"); if (p->sym_val_to_name[SYM_BOOLS]) { u32 q; for (q = 0; q < p->p_bools.nprim; q++) printf(" %s", p->sym_val_to_name[SYM_BOOLS][q] ? p->sym_val_to_name[SYM_BOOLS][q] : "-"); }
	printf(" idx:");
	if (p->bool_val_to_struct) { u32 q; for (q = 0; q < p->p_bools.nprim; q++) printf(" %d", p->bool_val_to_struct[q] ? p->bool_val_to_struct[q]->state : -9); }
	printf("\n");
}
static void dumplist(struct policydb *p)
{
	u32 i, q, k;
	printf("  cond_list len=%u\n", p->cond_list_len);
	for (i = 0; i < p->cond_list_len; i++) {
		struct cond_node *n = &p->cond_list[i];
		printf("   node %u state=%d expr:", i, n->cur_state);
		for (q = 0; q < n->expr.len; q++) printf(" %u.%u", n->expr.nodes[q].expr_type, n->expr.nodes[q].boolean);
		for (k = 0; k < 2; k++) {
			struct cond_av_list *l = k ? &n->false_list : &n->true_list;
			printf(" %s[%u]:", k ? "F" : "T", l->len);
			for (q = 0; q < l->len; q++) printf(" %u,%u,%u,%x", l->nodes[q]->key.source_type, l->nodes[q]->key.target_type, l->nodes[q]->key.target_class, l->nodes[q]->key.specified);
		}
		printf("\n");
	}
	dumpav(&p->te_cond_avtab);
}
static int cmpcount;
static void teardown(struct policydb *p)
{
	cond_policydb_destroy(p);
	if (p->p_bools.table.htable) { hashtab_map(&p->p_bools.table, cond_destroy_bool, NULL); hashtab_destroy(&p->p_bools.table); }
	avtab_destroy(&p->te_avtab);
	if (p->sym_val_to_name[SYM_BOOLS]) { free(p->sym_val_to_name[SYM_BOOLS]); live--; }
	memset(p, 0, sizeof *p);
}
static int clean;
#define RND0(n) (!clean && rnd(n) == 0)
static void putitem(unsigned char *buf, size_t *L, int cond)
{
	/* one avtab item, new format (version 34) */
	u16 s = 1 + rnd(3), t = 1 + rnd(3), cl = 1 + rnd(2), spec = specs[rnd(7)]; size_t q = *L;
	if (RND0(15)) s = 1 + rnd(9);
	if (RND0(25)) spec = (u16)rnd64();
	if (rnd(8) == 0) spec |= AVTAB_ENABLED;
	put16(buf + q, s); put16(buf + q + 2, t); put16(buf + q + 4, cl); put16(buf + q + 6, spec); q += 8;
	if (spec & AVTAB_XPERMS) { int k; buf[q++] = 1 + rnd(3); buf[q++] = rnd(256); for (k = 0; k < 8; k++) { put32(buf + q, rnd(2) ? 0 : (u32)rnd64()); q += 4; } }
	else { put32(buf + q, (spec & AVTAB_TYPE) ? 1 + rnd(7) : (u32)rnd64() >> rnd(32)); q += 4; }
	*L = q;
}
static int okp_flag;
static void setup(struct policydb *p, long it)
{
	okp_flag = 1; clean = rnd(10) < 7;
	unsigned nb = rnd(6), i; int rc;
	teardown(p);
	p->policyvers = rnd(8) ? 34 : 33; p->p_types.nprim = 6; p->p_classes.nprim = 4;
	rc = symtab_init(&p->p_bools, !RND0(4) ? nb : 0);
	p->p_bools.nprim = nb;
	printf("%ld setup nb=%u vers=%u symtab_init=%d\n", it, nb, p->policyvers, rc);
	for (i = 0; i < nb + (RND0(8)); i++) {
		unsigned char buf[64]; struct policy_file fp; size_t L = 0; char nm[8]; size_t nl = 1 + rnd(3), q;
		u32 val = RND0(10) ? 0 : RND0(10) ? nb + 1 : 1 + i, st = RND0(12) ? 2 : rnd(2);
		for (q = 0; q < nl; q++) nm[q] = 'a' + (RND0(8) ? rnd(3) : (i + q) % 5);
		put32(buf, val); put32(buf + 4, st); put32(buf + 8, RND0(15) ? 0 : nl); L = 12; memcpy(buf + L, nm, nl); L += nl;
		if (RND0(15)) L = rnd(L + 1);
		fp.data = (char *)buf; fp.len = L; fail_in = RND0(30) ? 1 + rnd(3) : 0;
		rc = cond_read_bool(p, &p->p_bools, &fp); fail_in = 0;
		printf("  read_bool %u -> %d\n", i, rc); if (rc) okp_flag = 0;
	}
	p->sym_val_to_name[SYM_BOOLS] = calloc(nb ? nb : 1, sizeof(char *)); live++;
	fail_in = RND0(20) ? 1 : 0; rc = cond_init_bool_indexes(p); fail_in = 0; printf("  init_bool_indexes -> %d\n", rc); if (rc) okp_flag = 0;
	if (rnd(6) == 0) { rc = cond_init_bool_indexes(p); printf("  init_bool_indexes again -> %d\n", rc); if (rc) okp_flag = 0; }
	if (p->bool_val_to_struct) { rc = hashtab_map(&p->p_bools.table, cond_index_bool, p); printf("  index_bool -> %d\n", rc); if (rc) okp_flag = 0; }
	dumpbools(p);
	avtab_alloc(&p->te_avtab, 8);
	for (i = 0, rc = rnd(24); i < rc; i++) { struct avtab_key k = { 1 + rnd(3), 1 + rnd(3), 1 + rnd(2), specs[3 + rnd(3)] }; struct avtab_datum d = { .u.data = 1 + rnd(7) }; avtab_insert_nonunique(&p->te_avtab, &k, &d); }
	/* the conditional list */
	{
		unsigned char *buf = malloc(8192); struct policy_file fp; size_t L = 0; unsigned n = rnd(4), ni;
		put32(buf, RND0(40) ? 3 : n); L = 4; if (RND0(40)) n = 3;
		for (ni = 0; ni < n; ni++) {
			unsigned el, q, k;
			if (clean) {
				/* a well-formed reverse-Polish expression, sometimes deep enough to overflow the evaluator's stack of 10 */
				int depth = 0; unsigned want = rnd(10) == 0 ? 11 + rnd(4) : 1 + rnd(6); unsigned char *eb = buf + L + 8;
				el = 0;
				while (el < want || depth > 1) {
					u32 ty, bo = 0;
					if (depth >= 2 && (el >= want || rnd(2))) { ty = 3 + rnd(5); if (ty > 7) ty = 7; depth--; if (rnd(8) == 0 && depth >= 1) { ty = 2; depth++; } }
					else if (depth >= 1 && rnd(6) == 0) { ty = 2; }
					else { ty = 1; bo = 1 + rnd(nb ? nb : 1); depth++; }
					if (ty == 2 && depth < 1) { ty = 1; bo = 1 + rnd(nb ? nb : 1); depth++; }
					put32(eb, ty); put32(eb + 4, bo); eb += 8; el++;
				}
				put32(buf + L, rnd(3) == 0 ? 0xffffffffu : rnd(2)); put32(buf + L + 4, el); L += 8 + 8 * el;
			} else {
				el = RND0(10) ? rnd(14) : 1 + rnd(5);
				put32(buf + L, rnd(3) == 0 ? 0xffffffffu : rnd(2)); put32(buf + L + 4, el); L += 8;
				for (q = 0; q < el; q++) {
					u32 ty = RND0(12) ? rnd(10) : (rnd(3) == 0 ? 1 + rnd(7) : 1), bo = RND0(15) ? rnd(nb + 3) : 1 + rnd(nb ? nb : 1);
					put32(buf + L, ty); put32(buf + L + 4, bo); L += 8;
				}
			}
			for (k = 0; k < 2; k++) { unsigned li = rnd(3), z; put32(buf + L, li); L += 4; for (z = 0; z < li; z++) putitem(buf, &L, 1); }
		}
		if (RND0(10)) L = rnd(L + 1);
		{ unsigned char *ex = malloc(L ? L : 1); memcpy(ex, buf, L); free(buf);
		  fp.data = (char *)ex; fp.len = L; fail_in = RND0(20) ? 1 + rnd(6) : 0;
		  rc = cond_read_list(p, &fp); fail_in = 0; printf("  read_list len=%zu -> %d left=%zu\n", L, rc, fp.len); if (rc) okp_flag = 0; free(ex); }
	}
	dumplist(p);
	{ u32 q; for (q = 0; q < p->p_bools.nprim; q++) if (!p->bool_val_to_struct || !p->bool_val_to_struct[q]) okp_flag = 0; }
}
#define K 2
static struct policydb pol[K];
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 12000, it, pc = 0; int i, rc;
	struct kmem_cache c1, c2, c3; avtab_node_cachep = &c1; avtab_xperms_cachep = &c2; hashtab_node_cachep = &c3;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		int op = rnd(100); struct policydb *p;
		i = rnd(K); p = &pol[i];
		if (!pol[i].p_bools.nprim && !pol[i].cond_list && !pol[i].p_bools.table.htable && op >= 5) op = 0;
		if (op < 8) { setup(p, it); if (!okp_flag) { teardown(p); printf("%ld rejected %d\n", it, i); } }
		else if (op < 30) {
			u32 q;
			for (q = 0; q < p->p_bools.nprim; q++) if (p->bool_val_to_struct && p->bool_val_to_struct[q] && rnd(2)) p->bool_val_to_struct[q]->state = rnd(10) == 0 ? -1 : rnd(2);
			evaluate_cond_nodes(p); if (prove && p->cond_list_len && pc++ == 3) p->cond_list[0].cur_state ^= 1;
			printf("%ld evaluate %d\n", it, i); dumpbools(p); dumplist(p);
		} else if (op < 55) {
			struct avtab_key k = { 1 + rnd(3), 1 + rnd(3), 1 + rnd(2), specs[rnd(7)] }; struct av_decision avd = { rnd(2) ? 0 : (u32)rnd64(), (u32)rnd64() & 0xf0f, 0xffffffffu >> rnd(20), 0, 0 }; struct extended_perms xp;
			if (rnd(10) < 7 && p->te_cond_avtab.nel) { u32 s0 = rnd(p->te_cond_avtab.nslot), t; for (t = 0; t < p->te_cond_avtab.nslot; t++) if (p->te_cond_avtab.htable[(s0 + t) % p->te_cond_avtab.nslot]) { k = p->te_cond_avtab.htable[(s0 + t) % p->te_cond_avtab.nslot]->key; k.specified &= ~AVTAB_ENABLED; break; } }
			struct avtab_key *kp = rnd(15) == 0 ? NULL : &k; struct av_decision *ap = rnd(15) == 0 ? NULL : &avd; struct avtab *ct = rnd(15) == 0 ? NULL : &p->te_cond_avtab;
			cond_compute_av(ct, kp, ap, rnd(2) ? &xp : NULL);
			printf("%ld compute_av %d %u,%u,%u,%x -> %x %x %x\n", it, i, k.source_type, k.target_type, k.target_class, k.specified, avd.allowed, avd.auditallow, avd.auditdeny);
		} else if (op < 62) {
			struct avtab_key k = { 1 + rnd(3), 1 + rnd(3), 1 + rnd(2), AVTAB_XPERMS_ALLOWED }; struct extended_perms_decision xd;
			if (rnd(10) < 7 && p->te_cond_avtab.nel) { u32 s0 = rnd(p->te_cond_avtab.nslot), t; for (t = 0; t < p->te_cond_avtab.nslot; t++) if (p->te_cond_avtab.htable[(s0 + t) % p->te_cond_avtab.nslot]) { k = p->te_cond_avtab.htable[(s0 + t) % p->te_cond_avtab.nslot]->key; k.specified &= ~AVTAB_ENABLED; break; } }
			cond_compute_xperms(rnd(15) ? &p->te_cond_avtab : NULL, rnd(15) ? &k : NULL, rnd(15) ? &xd : NULL); printf("%ld compute_xperms %d\n", it, i);
		} else if (op < 75) {
			static unsigned char buf[8192]; struct policy_file fp; struct policy_data pd; size_t L = rnd(4) == 0 ? rnd(60) : sizeof buf; u32 s; struct hashtab_node *hn; size_t used;
			memset(buf, 0xaa, sizeof buf); fp.data = (char *)buf; fp.len = L; pd.p = p; pd.fp = &fp; rc = 0;
			for (s = 0; s < p->p_bools.table.size && !rc; s++) for (hn = p->p_bools.table.htable[s]; hn && !rc; hn = hn->next) rc = cond_write_bool(hn->key, hn->datum, &pd);
			used = L - fp.len; printf("%ld write_bools %d len=%zu -> %d used=%zu ", it, i, L, rc, used); { size_t q; for (q = 0; q < used && q < 100; q++) printf("%02x", buf[q]); } printf("\n");
			rc = cond_write_list(p, &fp); printf("   write_list -> %d used=%zu ", rc, L - used - fp.len);
			{ size_t q; for (q = used; q < L - fp.len && q < used + 100; q++) printf("%02x", buf[q]); } printf("\n");
		} else if (op < 90) {
			struct policydb *nw = calloc(1, sizeof *nw); nw->bool_val_to_struct = (struct cond_bool_datum **)0x10; nw->cond_list = (struct cond_node *)0x10; nw->cond_list_len = 0xdead; nw->te_cond_avtab.htable = (struct avtab_node **)0x10; nw->te_cond_avtab.nel = 0xbeef; nw->te_cond_avtab.nslot = 0xbeef; nw->te_cond_avtab.mask = 0xbeef;
			fail_in = rnd(3) == 0 ? 1 + rnd(30) : 0;
			rc = cond_policydb_dup(nw, p); fail_in = 0;
			printf("%ld dup %d -> %d\n", it, i, rc);
			if (rc == 0) { dumpbools(nw); dumplist(nw); cond_policydb_destroy_dup(nw); }
			else printf("  after failure: list=%d idx=%d boolsel=%u\n", nw->cond_list != NULL, nw->bool_val_to_struct != NULL, nw->p_bools.table.nel);
			free(nw);
		} else { teardown(p); printf("%ld teardown %d\n", it, i); }
	}
	for (i = 0; i < K; i++) teardown(&pol[i]);
	printf("live at the end: %ld %ld %ld\n", live, live_nodes, allocs > 0);
	return 0;
}
