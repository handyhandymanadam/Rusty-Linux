/* SELinux MLS differential: the pristine mls.c (ARM_REF) against mls_rs.rs with the glue's wrapper (ARM_RS); ebitmap, hashtab and symtab are the pristine C in both. Two random policies are kept
 * (A and B): 1-5 sensitivities and 1-900 categories under shuffled values, every level datum with a random category set, users with random ranges and default levels, classes with a default range
 * (0-8), range transitions, a process class, MLS on in nine of ten. Each round picks one operation: parse a context string (valid ones, ranges, stray separators, unknown names, backwards ranges,
 * truncations; pre-filled bitmaps; allocation failures) and print the string as it is left (the C code writes NULs into it), measure and print a context, the three validity checks on contexts that
 * are valid and contexts that are not, mls_range_set, mls_setup_user_range, mls_convert_context from A to B, mls_compute_sid with every specified value and class.  Every result and the
 * contexts it leaves are printed.   usage: t SHARD (env EB_N, EB_PROVE) */
#include "refshim.h"
#include "ebitmap.h"
#include "sidtab.h"
#include "mls.h"
#include "policydb.h"
#include "context.h"
struct kmem_cache *ebitmap_node_cachep, *hashtab_node_cachep;
long fail_in, live_nodes, allocs, live, live_strs, resched_count; unsigned long gfp_log;

/* ---- the sid table and range transitions ---- */
static struct context sids[8]; static int nsids;
struct context *sidtab_search(struct sidtab *s, u32 sid) { return (sid >= 1 && sid <= (u32)nsids) ? &sids[sid - 1] : NULL; }
static struct { u32 src, tgt; u16 cls; struct mls_range r; } rtr[6]; static int nrtr;
struct mls_range *policydb_rangetr_search(struct policydb *p, struct range_trans *key)
{
	int i;
	for (i = 0; i < nrtr; i++)
		if (rtr[i].src == key->source_type && rtr[i].tgt == key->target_type && rtr[i].cls == key->target_class) return &rtr[i].r;
	return NULL;
}
#include SRCFILE

static unsigned long long rs_;
static unsigned long long rnd64(void) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return (rs_ >> 11) ^ (rs_ << 53); }
static unsigned rnd(unsigned n) { return n ? (unsigned)(rnd64() % n) : 0; }

/* ---- policies ---- */
struct pol { struct policydb p; int nlev, ncat, nusr, ncls; char *lname[8]; char **cname; struct level_datum ld[8]; struct cat_datum *cd; struct user_datum ud[4]; struct user_datum *uarr[4];
	     struct class_datum cl[5]; struct class_datum *carr[5]; char *lnames_by_val[8]; };
static struct pol PA, PB;
static const char *const lvpfx[8] = { "s", "sx", "sxy", "sxyz", "sxyzw", "sxyzwv", "sxyzwvu", "sxyzwvut" };
static void randset(struct ebitmap *e, int ncat, int density)
{
	int i, base = rnd(3) == 0 ? rnd(ncat) : 0, cnt = rnd(density + 1);
	for (i = 0; i < cnt; i++) { int b = rnd(4) == 0 ? base + rnd(5) : rnd(ncat); if (b >= ncat) b = ncat - 1; ebitmap_set_bit(e, b, 1); }
	if (rnd(4) == 0) { int a = rnd(ncat), n = rnd(40); for (i = 0; i < n && a + i < ncat; i++) ebitmap_set_bit(e, a + i, 1); }
}
static void freepol(struct pol *q)
{
	int i;
	if (!q->p.symtab[SYM_LEVELS].table.htable && !q->cd) return;
	for (i = 0; i < q->nlev; i++) ebitmap_destroy(&q->ld[i].level.cat);
	for (i = 0; i < q->nusr; i++) { ebitmap_destroy(&q->ud[i].range.level[0].cat); ebitmap_destroy(&q->ud[i].range.level[1].cat); ebitmap_destroy(&q->ud[i].dfltlevel.cat); }
	hashtab_destroy(&q->p.symtab[SYM_LEVELS].table); hashtab_destroy(&q->p.symtab[SYM_CATS].table);
	for (i = 0; i < q->ncat; i++) free(q->cname[i]);
	for (i = 0; i < q->nlev; i++) free(q->lname[i]);
	free(q->cname); free(q->cd); free(q->p.sym_val_to_name[SYM_CATS]); free(q->p.sym_val_to_name[SYM_LEVELS]);
	memset(q, 0, sizeof(*q));
}
static void mkpol(struct pol *q, int shared_names)
{
	int i, j; int perm[900], lperm[8]; long fi = fail_in; static const int sizes[] = { 1, 2, 3, 5, 9, 20, 64, 130, 400, 900 };
	fail_in = 0; freepol(q);
	q->p.mls_enabled = rnd(10) != 0;
	q->nlev = 1 + rnd(5); q->ncat = sizes[rnd(10)]; q->nusr = 1 + rnd(3); q->ncls = rnd(5);
	for (i = 0; i < q->ncat; i++) perm[i] = i;
	for (i = q->ncat - 1; i > 0; i--) { j = rnd(i + 1); int t = perm[i]; perm[i] = perm[j]; perm[j] = t; }
	for (i = 0; i < q->nlev; i++) lperm[i] = i;
	for (i = q->nlev - 1; i > 0; i--) { j = rnd(i + 1); int t = lperm[i]; lperm[i] = lperm[j]; lperm[j] = t; }
	symtab_init(&q->p.symtab[SYM_LEVELS], 8); symtab_init(&q->p.symtab[SYM_CATS], 16);
	q->p.symtab[SYM_LEVELS].nprim = q->nlev; q->p.symtab[SYM_CATS].nprim = q->ncat;
	q->p.sym_val_to_name[SYM_LEVELS] = calloc(q->nlev, sizeof(char *)); q->p.sym_val_to_name[SYM_CATS] = calloc(q->ncat, sizeof(char *));
	q->cname = calloc(q->ncat, sizeof(char *)); q->cd = calloc(q->ncat, sizeof(*q->cd));
	for (i = 0; i < q->nlev; i++) {
		char buf[24]; snprintf(buf, sizeof buf, "%s%d", lvpfx[i], i); q->lname[i] = strdup(buf);	/* name s<i> gets value lperm[i] + 1 */
		q->ld[i].level.sens = lperm[i] + 1;
		randset(&q->ld[i].level.cat, q->ncat, rnd(3) == 0 ? 3 : q->ncat);
		if (rnd(3) == 0) { int b; for (b = 0; b < q->ncat; b++) ebitmap_set_bit(&q->ld[i].level.cat, b, 1); }
		if (rnd(3) == 0) { int b; for (b = 0; b < 30; b++) ebitmap_set_bit(&q->ld[i].level.cat, q->ncat + rnd(60), 1); }	/* a level datum with categories the policy does not have */
		symtab_insert(&q->p.symtab[SYM_LEVELS], q->lname[i], &q->ld[i]);
		q->p.sym_val_to_name[SYM_LEVELS][lperm[i]] = q->lname[i];
	}
	for (i = 0; i < q->ncat; i++) {
		char buf[16]; snprintf(buf, sizeof buf, "c%d", i); q->cname[i] = strdup(buf);
		q->cd[i].value = perm[i] + 1;
		symtab_insert(&q->p.symtab[SYM_CATS], q->cname[i], &q->cd[i]);
		q->p.sym_val_to_name[SYM_CATS][perm[i]] = q->cname[i];
	}
	q->p.symtab[SYM_LEVELS].nprim = q->nlev; q->p.symtab[SYM_CATS].nprim = q->ncat;
	q->p.symtab[SYM_USERS].nprim = q->nusr; q->p.symtab[SYM_CLASSES].nprim = q->ncls;
	for (i = 0; i < q->nusr; i++) {
		int k; for (k = 0; k < 2; k++) { q->ud[i].range.level[k].sens = 1 + rnd(q->nlev + 1); randset(&q->ud[i].range.level[k].cat, q->ncat, 30); }
		q->ud[i].dfltlevel.sens = 1 + rnd(q->nlev); randset(&q->ud[i].dfltlevel.cat, q->ncat, 30);
		if (rnd(2)) { q->ud[i].range.level[0].sens = 1; ebitmap_destroy(&q->ud[i].range.level[0].cat); }
		q->uarr[i] = &q->ud[i];
	}
	q->p.user_val_to_struct = q->uarr;
	for (i = 0; i < q->ncls; i++) { q->cl[i].default_range = rnd(10) < 7 ? rnd(9) : 0; q->carr[i] = rnd(6) ? &q->cl[i] : NULL; }
	q->p.class_val_to_struct = q->carr;
	q->p.process_class = rnd(q->ncls + 3);
	fail_in = fi;
}

/* ---- contexts ---- */
static void dumpeb(const struct ebitmap *e)
{
	const struct ebitmap_node *n; int j;
	printf(" high=%u", e->highbit);
	for (n = e->node; n; n = n->next) { printf(" {%u", n->startbit); for (j = 0; j < 6; j++) if (n->maps[j]) printf(" %d:%llx", j, (unsigned long long)n->maps[j]); printf("}"); }
}
static void dumpctx(const char *tag, const struct context *c)
{
	printf("  %s u=%u r=%u t=%u lo=%u", tag, c->user, c->role, c->type, c->range.level[0].sens); dumpeb(&c->range.level[0].cat);
	printf(" hi=%u", c->range.level[1].sens); dumpeb(&c->range.level[1].cat); printf("\n");
}
static void freectx(struct context *c)
{
	ebitmap_destroy(&c->range.level[0].cat); ebitmap_destroy(&c->range.level[1].cat); memset(c, 0, sizeof(*c));
}
/* a random context for policy q; ok = 1: values the policy knows */
static void randctx(struct context *c, struct pol *q, int ok)
{
	int k;
	long fi = fail_in; fail_in = 0;
	memset(c, 0, sizeof(*c));
	c->user = ok ? 1 + rnd(q->nusr) : rnd(q->nusr + 3); c->role = rnd(4) ? 2 : 1; c->type = rnd(5);
	for (k = 0; k < 2; k++) {
		c->range.level[k].sens = ok ? 1 + rnd(q->nlev) : (rnd(4) == 0 ? rnd(q->nlev + 3) : 1 + rnd(q->nlev));
		randset(&c->range.level[k].cat, ok ? q->ncat : q->ncat + 40, rnd(2) ? 4 : 30);
		if (ok && rnd(2) && k == 1) { ebitmap_destroy(&c->range.level[1].cat); ebitmap_cpy(&c->range.level[1].cat, &c->range.level[0].cat); c->range.level[1].sens = c->range.level[0].sens; }
		if (ok && k == 1 && rnd(3) == 0) { int b; for (b = 0; b < 3; b++) ebitmap_set_bit(&c->range.level[1].cat, rnd(q->ncat), 1); }
	}
	fail_in = fi;
}
/* a context string for policy q */
static void randstr(char *buf, size_t n, struct pol *q)
{
	int part, np = rnd(10) < 4 ? 2 : 1; size_t o = 0; int sens_ok;
	buf[0] = 0;
	for (part = 0; part < np; part++) {
		int nc = rnd(4) == 0 ? 0 : rnd(6), i;
		sens_ok = rnd(12) != 0;
		{ int li = rnd(q->nlev + (rnd(8) == 0 ? 2 : 0)); o += snprintf(buf + o, n - o, "%s%s%d", part ? "-" : "", sens_ok ? lvpfx[li] : "x", li); }
		if (nc) o += snprintf(buf + o, n - o, ":");
		for (i = 0; i < nc; i++) {
			int a = rnd(q->ncat + (rnd(15) == 0 ? 3 : 0)), b = rnd(q->ncat + (rnd(15) == 0 ? 3 : 0));
			if (rnd(3) == 0 && q->ncat > 1) { if (rnd(8) != 0 && b < a) { int t = a; a = b; b = t; } o += snprintf(buf + o, n - o, "%sc%d.c%d", i ? "," : "", a, b); }
			else o += snprintf(buf + o, n - o, "%sc%d", i ? "," : "", a);
		}
	}
	if (rnd(10) == 0) { size_t len = strlen(buf); if (len) { size_t at = rnd(len); switch (rnd(4)) { case 0: buf[at] = ",.:-"[rnd(4)]; break; case 1: buf[at] = 0; break; case 2: buf[at] = 'z'; break; default: memmove(buf + at + 1, buf + at, len - at + 1); buf[at] = ",.:-"[rnd(4)]; } } }
}
static void dumpstr(const char *s, size_t n) { size_t i; printf("  str:"); for (i = 0; i < n; i++) putchar(s[i] ? s[i] : '|'); putchar('\n'); }

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0, prove = getenv("EB_PROVE") != NULL; long n = getenv("EB_N") ? atol(getenv("EB_N")) : 30000, it; int pc = 0, rc, i;
	struct kmem_cache cache; ebitmap_node_cachep = &cache; hashtab_node_cachep = &cache;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (it = 0; it < n; it++) {
		int op = rnd(100); struct pol *P = &PA; struct context c = {0}, d = {0}, e = {0}, f = {0};
		if (it % 25 == 0) { mkpol(&PA, 0); mkpol(&PB, 0); nrtr = 0; nsids = 0; }
		if (it % 25 == 0 || rnd(40) == 0) {	/* sid table and range transitions follow the policy */
			for (i = 0; i < nsids; i++) freectx(&sids[i]);
			nsids = 1 + rnd(4); for (i = 0; i < nsids; i++) randctx(&sids[i], &PA, 1);
			for (i = 0; i < nrtr; i++) { ebitmap_destroy(&rtr[i].r.level[0].cat); ebitmap_destroy(&rtr[i].r.level[1].cat); }
			nrtr = rnd(4); for (i = 0; i < nrtr; i++) { memset(&rtr[i], 0, sizeof(rtr[i])); rtr[i].src = rnd(5); rtr[i].tgt = rnd(5); rtr[i].cls = rnd(PA.ncls + 2); rtr[i].r.level[0].sens = 1 + rnd(PA.nlev); rtr[i].r.level[1].sens = 1 + rnd(PA.nlev); randset(&rtr[i].r.level[0].cat, PA.ncat, 6); randset(&rtr[i].r.level[1].cat, PA.ncat, 6); }
		}
		fail_in = rnd(8) == 0 ? 1 + rnd(5) : 0;
		if (op < 30) {
			char buf[160], orig[160];
			memset(buf, 0, sizeof buf); randstr(buf, sizeof buf, P); memcpy(orig, buf, sizeof buf);
			if (rnd(3) == 0) randset(&c.range.level[0].cat, P->ncat, 5);
			if (rnd(5) == 0) c.range.level[1].sens = 77;
			{ char oldc = rnd(10) == 0 ? 0 : (rnd(10) == 0 ? 'x' : ':'); u32 def = rnd(3) == 0 ? rnd(nsids + 2) : 0;
			  rc = mls_context_to_sid(&P->p, oldc, buf, &c, (struct sidtab *)&cache, def);
			  if (prove && pc++ == 3) rc ^= 1;
			  printf("%ld to_sid '%s' old=%d def=%u mls=%d -> %d\n", it, orig, oldc, def, P->p.mls_enabled, rc); }
			dumpstr(buf, strlen(orig) + 2); dumpctx("ctx", &c);
			freectx(&c);
		} else if (op < 45) {
			char out[40000], *o = out; int len;
			randctx(&c, P, 1);
			len = mls_compute_context_len(&P->p, &c);
			memset(out, 'Q', sizeof out);
			mls_sid_to_context(&P->p, &c, &o);
			printf("%ld to_str mls=%d len=%d written=%ld\n", it, P->p.mls_enabled, len, (long)(o - out)); dumpstr(out, o - out + 1); dumpctx("ctx", &c);
			freectx(&c);
		} else if (op < 60) {
			randctx(&c, P, rnd(2));
			printf("%ld valid mls=%d lvl0=%d lvl1=%d range=%d ctx=%d\n", it, P->p.mls_enabled, mls_level_isvalid(&P->p, &c.range.level[0]), mls_level_isvalid(&P->p, &c.range.level[1]),
			       mls_range_isvalid(&P->p, &c.range), mls_context_isvalid(&P->p, &c));
			dumpctx("ctx", &c); freectx(&c);
		} else if (op < 68) {
			randctx(&c, P, 1);
			if (rnd(3) == 0) randset(&d.range.level[1].cat, P->ncat, 5);
			rc = mls_range_set(&d, &c.range);
			printf("%ld range_set -> %d\n", it, rc); dumpctx("dst", &d); freectx(&c); freectx(&d);
		} else if (op < 78) {
			struct user_datum *u = P->uarr[rnd(P->nusr)];
			randctx(&c, P, 1);
			if (rnd(2)) { u->range.level[0].sens = c.range.level[0].sens; u->range.level[1].sens = c.range.level[1].sens; }
			if (rnd(2)) u->dfltlevel.sens = c.range.level[rnd(2)].sens;
			rc = mls_setup_user_range(&P->p, &c, u, &d);
			printf("%ld setup_user mls=%d -> %d\n", it, P->p.mls_enabled, rc); dumpctx("from", &c); dumpctx("user", &d);
			memset(&d, 0, sizeof(d)); freectx(&c);
		} else if (op < 88) {
			randctx(&c, &PA, 1); if (rnd(4) == 0) randset(&d.range.level[0].cat, PB.ncat, 4);
			rc = mls_convert_context(&PA.p, &PB.p, &c, &d);
			printf("%ld convert A.mls=%d B.mls=%d -> %d\n", it, PA.p.mls_enabled, PB.p.mls_enabled, rc); dumpctx("old", &c); dumpctx("new", &d); freectx(&c); freectx(&d);
		} else {
			static const u32 specs[] = { 0x10, 0x20, 0x40, 0x10, 0x40, 0x1, 0x80 };
			u16 cls = rnd(4) == 0 ? rtr[0].cls : rnd(P->ncls + 3); u32 sp = specs[rnd(7)]; bool sock = rnd(3) == 0;
			randctx(&c, P, 1); randctx(&e, P, 1);
			if (nrtr && rnd(3) == 0) { c.type = rtr[0].src; e.type = rtr[0].tgt; cls = rtr[0].cls; }
			if (rnd(3) == 0 && P->ncls > 0) { cls = 1 + rnd(P->ncls); sp = 0x10; if (P->carr[cls - 1]) P->carr[cls - 1]->default_range = 7; }	/* the greatest lower bound / least upper bound path */
			if (rnd(2)) { int k; for (k = 0; k < 2; k++) { ebitmap_destroy(&e.range.level[k].cat); ebitmap_cpy(&e.range.level[k].cat, &c.range.level[rnd(2)].cat); if (rnd(3)) e.range.level[k].sens = c.range.level[rnd(2)].sens; } }
			rc = mls_compute_sid(&P->p, &c, &e, cls, sp, &d, sock);
			printf("%ld compute_sid mls=%d class=%u proc=%u spec=%x sock=%d -> %d\n", it, P->p.mls_enabled, cls, P->p.process_class, sp, sock, rc); dumpctx("src", &c); dumpctx("tgt", &e); dumpctx("new", &d);
			freectx(&c); freectx(&e); freectx(&d);
		}
	}
	printf("live_nodes=%ld live=%ld live_strs=%ld\n", live_nodes, live, live_strs);
	return 0;
}
