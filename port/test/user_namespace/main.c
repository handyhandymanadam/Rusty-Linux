/* user_namespace id-map differential: the pristine slice (ARM_REF: ref.c) against user_namespace_rs.rs (ARM_RS). Random /proc/PID/uid_map texts (valid, overlapping, wrapping, with junk,
 * blank lines, CR/NBSP separators, up to 340+ lines so the 6th-extent switch and the sorted arrays are used), then parent translation, sort, and lookups. Prints the parse result, the
 * whole map, and the answer to every lookup.   usage: t SHARD (env UN_N, UN_PROVE=1) */
#include "refshim.h"
long allocs_out, alloc_fail_in = -1;
void *t_alloc(size_t n) { if (alloc_fail_in >= 0 && alloc_fail_in-- == 0) { alloc_fail_in = -1; return NULL; } allocs_out++; return malloc(n ? n : 1); }
int t_isspace(int c) { unsigned char u = (unsigned char)c; return (u >= 9 && u <= 13) || u == 32 || u == 0xa0; }
char *skip_spaces(const char *s) { while (t_isspace(*s)) ++s; return (char *)s; }
/* lib/vsprintf.c simple_strtoul: digits only, no sign or whitespace, wraps modulo 2^64 */
unsigned long simple_strtoul(const char *cp, char **endp, unsigned base)
{
	unsigned long long r = 0; const char *p = cp;
	if (base != 10) abort();
	while (*p >= '0' && *p <= '9') { r = r * 10 + (*p - '0'); p++; }
	if (endp) *endp = (char *)p;
	return r;
}
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void *swap) { (void)swap; qsort(base, num, size, cmp); }
void *bsearch(const void *key, const void *base, size_t num, size_t size, int (*cmp)(const void *, const void *))
{
	const char *b = base;
	while (num > 0) {
		const char *p = b + (num >> 1) * size; int r = cmp(key, p);
		if (r == 0) return (void *)p;
		if (r > 0) { b = p + size; num--; }
		num >>= 1;
	}
	return NULL;
}
#ifdef ARM_REF
#include "ref.c"
#define T_PARSE ref_parse
#define T_REMAP ref_remap
#define T_SORT ref_sort
#define T_DOWN ref_down
#define T_UP ref_up
static u32 T_RUP(struct uid_gid_map *m, u32 id, u32 c) { return map_id_range_up(m, id, c); }
#else
int rust_userns_parse(char *, struct uid_gid_map *); int rust_userns_remap(struct uid_gid_map *, struct uid_gid_map *); int rust_userns_sort(struct uid_gid_map *);
u32 rust_map_id_down(struct uid_gid_map *, u32); u32 rust_map_id_up(struct uid_gid_map *, u32); u32 rust_map_id_range_up(struct uid_gid_map *, u32, u32);
/* the four wrappers of user_namespace_glue.c */
void *rust_un_bsearch(const void *key, const void *base, size_t num, int (*cmp)(const void *, const void *)) { return bsearch(key, base, num, sizeof(struct uid_gid_extent), cmp); }
struct uid_gid_extent *rust_un_alloc_extents(size_t n) { return kmalloc_array(n, sizeof(struct uid_gid_extent), GFP_KERNEL); }
struct uid_gid_extent *rust_un_dup_extents(const struct uid_gid_extent *src, size_t n) { return kmemdup_array(src, n, sizeof(struct uid_gid_extent), GFP_KERNEL); }
bool rust_un_isspace(char c) { return isspace(c); }
#define T_PARSE rust_userns_parse
#define T_REMAP rust_userns_remap
#define T_SORT rust_userns_sort
#define T_DOWN rust_map_id_down
#define T_UP rust_map_id_up
#define T_RUP rust_map_id_range_up
#endif

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }

static void pnum(char **p, unsigned long long v) { *p += sprintf(*p, "%llu", v); }
static const char *SEP[] = { " ", "  ", "\t", " \t ", "\xa0", "\r", "\v" };
static unsigned pick(unsigned lim) {  /* interesting 32-bit values */
	switch (rnd(8)) {
	case 0: return rnd(5); case 1: return 0xffffffffu - rnd(3); case 2: return 0x7fffffffu + rnd(3) - 1;
	case 3: return rnd(2000); case 4: return rnd(100000); default: return rnd(lim);
	}
}
/* a random map text: nlines lines of "first lower count"; mostly non-overlapping sorted-ish, sometimes junk */
static size_t mktext(char *b, int nlines, int mode, int junk)
{
	char *p = b; unsigned base_u = rnd(50), base_l = rnd(50); int swap = rnd(2);
	for (int i = 0; i < nlines; i++) {
		unsigned long long f, l, c;
		if (mode == 0) { c = 1 + rnd(40); f = base_u + (unsigned long long)i * 100 + rnd(30); l = base_l + (unsigned long long)i * 100 + rnd(30); if (swap) { unsigned long long t = f; f = l; l = t; } }
		else { f = pick(70000); l = pick(70000); c = rnd(3) ? 1 + rnd(50) : pick(100000); if (rnd(20) == 0) c = 0; }
		if (rnd(25) == 0) *p++ = ' ';
		pnum(&p, f); p += sprintf(p, "%s", SEP[rnd(rnd(8) ? 1 : 7)]);
		pnum(&p, l); p += sprintf(p, "%s", SEP[rnd(rnd(8) ? 1 : 7)]);
		pnum(&p, c);
		if (junk && rnd(40) == 0) p += sprintf(p, "x");
		if (junk && rnd(40) == 0) p += sprintf(p, " 7");
		if (rnd(30) == 0) p += sprintf(p, " ");
		if (i + 1 < nlines || rnd(2)) *p++ = '\n';
		if (junk && rnd(40) == 0) *p++ = '\n';
	}
	if (junk && rnd(60) == 0) p += sprintf(p, "99999999999999999999 1 1"); /* wraps */
	*p = 0;
	return (size_t)(p - b);
}
static void pmap(const char *tag, struct uid_gid_map *m, int w)
{
	printf(" %s n=%u", tag, m->nr_extents);
	if (m->nr_extents <= 5) { for (u32 i = 0; i < m->nr_extents; i++) printf(" (%u,%u,%u)", m->extent[i].first, m->extent[i].lower_first, m->extent[i].count); }
	else if (w) {
		for (u32 i = 0; i < m->nr_extents; i++) printf(" f(%u,%u,%u)", m->forward[i].first, m->forward[i].lower_first, m->forward[i].count);
		if (m->reverse) for (u32 i = 0; i < m->nr_extents; i++) printf(" r(%u,%u,%u)", m->reverse[i].first, m->reverse[i].lower_first, m->reverse[i].count);
		else printf(" rev=NULL");
	} else printf(" (big, %s)", m->reverse ? "rev" : "norev");
}
static void freemap(struct uid_gid_map *m) { if (m->nr_extents > 5) { if (m->forward) { free(m->forward); allocs_out--; } if (m->reverse) { free(m->reverse); allocs_out--; } } memset(m, 0, sizeof *m); }
static void lookups(struct uid_gid_map *m, int dense)
{
	unsigned long long h = 0; int n = 0;
	for (int k = 0; k < 400; k++) {
		u32 id = rnd(3) ? pick(70000) : (u32)(rnd(40) * 100 + rnd(60));
		if (m->nr_extents && rnd(2)) { u32 i = rnd(m->nr_extents); struct uid_gid_extent *e = m->nr_extents <= 5 ? &m->extent[i] : &m->forward[i]; u32 which = rnd(4); id = rnd(2) ? e->first + (which ? e->count - 1 + rnd(3) - 1 : rnd(2) - 1) : e->lower_first + (which ? e->count - 1 + rnd(3) - 1 : rnd(2) - 1); }
		u32 c = rnd(4) ? 1 : 1 + rnd(60);
		u32 d = T_DOWN(m, id), u = T_UP(m, id), ru = T_RUP(m, id, c);
		h = h * 1000003 + d; h = h * 1000003 + u; h = h * 1000003 + ru; n++;
		if (dense && k < 60) printf(" [%u:%u/%u/%u^%u]", id, d, u, ru, c);
	}
	printf(" lookups=%d h=%llu", n, h);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("UN_N") ? atol(getenv("UN_N")) : 6000; int prove = getenv("UN_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	static char buf[40000], tmp[40000];
	for (long s = 0; s < n; s++) {
		int big = rnd(6) == 0, nl = big ? 325 + rnd(30) : 1 + rnd(8), mode = rnd(3) ? 0 : 1;
		/* parent: a plain, always-valid identity-ish map from a small text */
		struct uid_gid_map par, nm; memset(&par, 0, sizeof par); memset(&nm, 0, sizeof nm);
		size_t len; unsigned pk = rnd(5);
		if (pk == 0) len = mktext(buf, 1 + rnd(rnd(4) ? 4 : 330), rnd(2), 1);
		else if (pk == 1) len = sprintf(buf, "0 0 4294967295\n");
		else if (pk == 2) len = sprintf(buf, "0 %u %u", rnd(5000), 100000000 + rnd(1000));
		else { char *q = buf; unsigned k = 1 + rnd(rnd(2) ? 8 : 400), sh = rnd(3000), st = 200 + rnd(300); for (unsigned i = 0; i < k; i++) q += sprintf(q, "%u %u %u\n", i * st, sh + i * (st + rnd(3)), st - rnd(4)); len = (size_t)(q - buf); }
		memcpy(tmp, buf, len + 1);
		alloc_fail_in = -1; int pr = T_PARSE(tmp, &par); if (pr == 0) pr = T_SORT(&par);
		if (pr < 0) { freemap(&par); memset(&par, 0, sizeof par); }
		len = mktext(buf, nl, mode, big ? rnd(4) == 0 : 1); memcpy(tmp, buf, len + 1);
		alloc_fail_in = rnd(12) == 0 ? rnd(4) : -1;
		int r = T_PARSE(tmp, &nm);
		printf("%ld parse=%d", s, r); pmap("new", &nm, !big);
		if (r == 0) {
			int r2 = T_REMAP(&nm, &par); printf(" remap=%d", r2); pmap("remapped", &nm, !big);
			if (r2 == 0) { int r3 = T_SORT(&nm); alloc_fail_in = -1; printf(" sort=%d", r3); pmap("sorted", &nm, !big); if (r3 == 0) lookups(&nm, !big); }
		}
		alloc_fail_in = -1;
		/* also look up in the parent */
		printf(" |parent"); pmap("p", &par, 0); lookups(&par, 0);
		printf(" live=%ld\n", allocs_out);
		freemap(&nm); freemap(&par);
		if (prove && s == 20) printf("  POISON\n");
	}
	printf("final live=%ld\n", allocs_out);
	return 0;
}
