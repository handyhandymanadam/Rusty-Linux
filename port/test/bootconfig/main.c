/* bootconfig differential: the same configuration texts drive pristine lib/bootconfig.c (ARM_REF) or bootconfig_glue.c over bootconfig_rs.rs (ARM_RS). For every text:
 * the result of xbc_init (nodes / error code, message, position), hashes of the node array and the data buffer, the finders, the leaf iteration, the command-line
 * rendering (size probe, full, truncated), xbc_get_info, a second init (-EBUSY), exit, and allocation-failure variants. usage: t SHARD (env BCF_N, BCF_PROVE=1) */
#include "kshim.h"
#include SRC

int warn_count, alloc_fail_in; long live_allocs;

char *skip_spaces(const char *str) { while (isspace(*str)) ++str; return (char *)str; }
char *strim(char *s)
{
	size_t size; char *end;
	size = strlen(s);
	if (!size) return s;
	end = s + size - 1;
	while (end >= s && isspace(*end)) end--;
	*(end + 1) = '\0';
	return skip_spaces(s);
}

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 33) % n : 0; }
static unsigned long long fnv(const void *p, size_t n) { const unsigned char *c = p; unsigned long long h = 1469598103934665603ULL; while (n--) { h ^= *c++; h *= 1099511628211ULL; } return h; }

/* ---- text generation ---- */
static char buf[70000]; static size_t blen;
static void put(const char *s) { size_t n = strlen(s); if (blen + n < sizeof(buf) - 1) { memcpy(buf + blen, s, n); blen += n; } }
static void putc_(char c) { if (blen + 1 < sizeof(buf) - 1) buf[blen++] = c; }
static const char *keys[] = { "a", "b", "kernel", "init", "foo", "bar", "x1", "key-2", "under_score", "A", "Z9", "feature", "alpha", "beta", "gamma", "k", "node", "list", "e" };
#define NK (sizeof(keys) / sizeof(keys[0]))
static const char *vals[] = { "1", "0", "yes", "on", "hello", "a b", "x,y", "", "tab\there", "q'uote", "d\"q", "#hash", "semi;colon", "brace}", "\xe9\xe8", "1.5", "long_value_long_value_long_value" };
#define NV (sizeof(vals) / sizeof(vals[0]))
static void gen_key(void)
{
	unsigned dots = rnd(4) == 0 ? 1 + rnd(5) : rnd(3) == 0 ? 1 : 0;
	if (rnd(150) == 0) { put(rnd(2) ? "bad key" : rnd(2) ? "k$" : "-"); return; }	/* invalid keywords */
	put(keys[rnd(NK)]);
	for (unsigned i = 0; i < dots; i++) { putc_('.'); put(keys[rnd(NK)]); }
	if (rnd(200) == 0) put(".");
}
static void gen_value(void)
{
	unsigned form = rnd(10);
	const char *v = vals[rnd(NV)];
	if (form == 0) { putc_('"'); put(v); if (rnd(8)) putc_('"'); }
	else if (form == 1) { putc_('\''); put(v); putc_('\''); }
	else if (form == 2) { for (unsigned i = 0, n = 1 + rnd(5); i < n; i++) { if (i) put(rnd(2) ? ", " : ","); if (rnd(3) == 0) { putc_('"'); put(vals[rnd(NV)]); putc_('"'); } else put(keys[rnd(NK)]); } }
	else if (form == 3 && rnd(20) == 0) { putc_((char)(1 + rnd(31))); }	/* non printable */
	else put(strpbrk(v, ",;#}\n\"'") ? keys[rnd(NK)] : v);
}
static void gen_stmt(int depth)
{
	unsigned k = rnd(12);
	for (unsigned i = rnd(3); i; i--) putc_(rnd(2) ? ' ' : '\t');
	if (k < 5) { gen_key(); put(rnd(60) == 0 ? " ::" : rnd(6) == 0 ? "+=" : rnd(6) == 0 ? ":=" : rnd(60) == 0 ? "+" : rnd(2) ? " = " : "="); gen_value(); put(rnd(3) ? "\n" : "; "); }
	else if (k < 7) { gen_key(); put(rnd(3) ? "\n" : ";"); }
	else if (k < 9 && depth < 18) { gen_key(); put(rnd(2) ? " {\n" : "{"); for (unsigned i = 1 + rnd(4); i; i--) gen_stmt(depth + 1); put(rnd(80) ? "}\n" : rnd(2) ? "}}\n" : "\n"); }
	else if (k == 9) { put("# comment "); put(vals[rnd(NV)]); put("\n"); }
	else if (k == 10) { put("\n"); }
	else { gen_key(); put(" = "); gen_value(); put(" # trailing\n"); }
}
static void gen_text(void)
{
	blen = 0;
	unsigned mode = rnd(40);
	if (mode == 0) { /* many nodes in under 32 KB: short unique keys, two nodes each, until the 8192-node limit is crossed (or not) */
		unsigned cnt = rnd(2) ? 4200 + rnd(100) : 3000 + rnd(1200);
		for (unsigned i = 0; i < cnt; i++) { char t[40]; snprintf(t, sizeof t, "n%x=1\n", i); put(t); } }
	else if (mode == 1) { /* too deep */ for (unsigned i = 0; i < 20; i++) { put(keys[rnd(NK)]); put(i < 19 ? "." : " = 1\n"); } }
	else if (mode == 2) { /* long key path */ for (unsigned i = 0; i < 40; i++) { put("verylongkeywordnumber"); put(i < 39 ? "." : " = 1\n"); } }
	else if (mode == 3) { /* deep braces */ for (unsigned i = 0; i < 20; i++) put("k {\n"); put("v=1\n"); for (unsigned i = 0; i < 20; i++) put("}\n"); }
	else if (mode == 4) { size_t n = rnd(3) ? 32760 + rnd(20) : 0; while (blen < n) put("kk=1\n"); }	/* around XBC_DATA_MAX */
	else { for (unsigned i = 1 + rnd(14); i; i--) gen_stmt(0); }
	if (rnd(5) == 0 && blen) { /* byte-level damage */ for (unsigned i = 1 + rnd(3); i; i--) { size_t p = rnd((unsigned)blen); buf[p] = rnd(3) ? "{}=+;:\n#\"', "[rnd(12)] : (char)rnd(256); } }
	if (rnd(30) == 0) blen = rnd((unsigned)blen + 1);	/* truncated */
	buf[blen] = 0;
}

/* ---- observation ---- */
static void observe(const char *tag)
{
	const char *emsg = NULL; int epos = 0, ret;
	long before = live_allocs;
	ret = xbc_init(buf, blen, &emsg, &epos);
	printf("%s init len=%zu -> %d msg=%s pos=%d warn=%d\n", tag, blen, ret, ret < 0 && emsg ? emsg : "-", epos, warn_count);
	if (ret > 0) {
		int nn = 0; size_t ds = 0;
		struct xbc_node *r = xbc_root_node();
		printf("  info=%d", xbc_get_info(&nn, &ds)); printf(" nodes=%d dsize=%zu nodehash=%016llx datahash=%016llx\n", nn, ds, fnv(r, 8 * (size_t)nn), fnv(xbc_data, xbc_data_size));
		/* iterate all key-value pairs */
		struct xbc_node *kn; const char *val; unsigned long long h = 0; int cnt = 0; char name[300];
		xbc_for_each_key_value(kn, val) {
			int cr = xbc_node_compose_key(kn, name, sizeof name);
			h = h * 1099511628211ULL ^ fnv(name, cr > 0 ? (size_t)cr : 0) ^ fnv(val, strlen(val)) ^ (unsigned)xbc_node_index(kn);
			if (cnt < 3) printf("   kv %s = %s (%d)\n", name, val, cr);
			cnt++;
		}
		printf("  leaves=%d kvhash=%016llx\n", cnt, h);
		/* every node as a starting point for next_leaf, parents, siblings */
		unsigned long long h2 = 0;
		for (int i = 0; i < nn; i++) {
			struct xbc_node *n = r + i;
			struct xbc_node *l = xbc_node_find_next_leaf(rnd(3) ? NULL : r + rnd(nn), n);
			struct xbc_node *p = xbc_node_get_parent(n), *c = xbc_node_get_child(n), *x = xbc_node_get_next(n);
			h2 = h2 * 31 + (l ? xbc_node_index(l) + 1 : 0) + 7 * (p ? xbc_node_index(p) + 1 : 0) + 13 * (c ? xbc_node_index(c) + 1 : 0) + 17 * (x ? xbc_node_index(x) + 1 : 0);
			h2 = h2 * 31 + fnv(xbc_node_get_data(n), strlen(xbc_node_get_data(n)));
			if (xbc_node_is_key(n) && i < 40) {
				char path[300]; struct xbc_node *vn = NULL;
				int cr = xbc_node_compose_key(n, path, sizeof path);
				const char *v = xbc_find_value(path, &vn);
				struct xbc_node *f = xbc_find_node(path);
				h2 = h2 * 31 + (v ? fnv(v, strlen(v)) : 7) + (vn ? xbc_node_index(vn) : -1) + (f ? xbc_node_index(f) : -1) + cr;
				/* perturbed probes */
				if (cr > 1) { path[rnd(cr)] ^= 1 << rnd(5); v = xbc_find_value(path, &vn); f = xbc_find_node(path); h2 = h2 * 31 + (v ? fnv(v, strlen(v)) : 3) + (f ? xbc_node_index(f) : -3); }
				path[rnd(cr > 0 ? cr : 1)] = 0; f = xbc_find_node(path); h2 = h2 * 31 + (f ? xbc_node_index(f) : -5);
			}
		}
		printf("  walkhash=%016llx\n", h2);
		/* command-line rendering: size probe, full, truncated, subtree */
		int need = xbc_snprint_cmdline(NULL, 0, NULL);
		char *cl = malloc(need > 0 ? need + 8 : 8); memset(cl, 0x55, need > 0 ? need + 8 : 8);
		int got = need > 0 ? xbc_snprint_cmdline(cl, need + 1, NULL) : -1;
		printf("  cmdline need=%d got=%d hash=%016llx", need, got, need > 0 ? fnv(cl, need) : 0);
		if (need > 4) { int tr = xbc_snprint_cmdline(cl, 1 + rnd(need), NULL); printf(" trunc=%d", tr); }
		struct xbc_node *sub = xbc_find_node(keys[rnd(NK)]);
		if (sub) printf(" sub=%d", xbc_snprint_cmdline(NULL, 0, sub));
		printf("\n"); free(cl);
		/* the finders with a bad iteration argument and the second init */
		{ const char *m2 = NULL; int e2 = 0; int r2 = xbc_init("a=1\n", 4, &m2, &e2); printf("  again=%d msg=%s pos=%d warn=%d\n", r2, m2 ? m2 : "-", e2, warn_count); }
		_xbc_exit(true);
		printf("  after exit: info=%d root=%d leak=%ld\n", xbc_get_info(NULL, NULL), xbc_root_node() != NULL, live_allocs - before);
	} else {
		printf("  leak=%ld info=%d\n", live_allocs - before, xbc_get_info(NULL, NULL));
	}
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("BCF_N") ? atol(getenv("BCF_N")) : 3000;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	/* a fixed corpus of corner cases */
	static const char *corpus[] = {
		"a=1\n", "a = 1", "a", "a;b;c", "", "  \n", "#only comment\n", "a=1\na+=2\na+=3\n", "a=1\na:=2\n", "a=1\na=2\n", "a.b.c=1\na.b.d=2\na.e=3\n",
		"a{b=1\n", "a{b=1}c=2", "}", "a {\n}\n", "a { b { c { d=1 } } }", "a=\"x\ny\"\n", "a=\"unterminated\n", "a='x',\"y\",z\n", "a=1,\n", "a=1,2,\n3\n",
		"a:b=1", "a+b=1", "a ?= 1", "a=1 b=2\n", "k = v # c\n", "a=b;c=d;e\n", "a.=1", ".a=1", "a..b=1", "a=\x01\n", "a.b=1\na=2\n", "a=1\na.b=2\n",
		"a=1,2\na:=3\n", "a=1,2\na+=3,4\n", "a{b=1,2}\n", "a=\"x\"y\n", "a = \"x\"  ; b=1", "a\n{\nb=1\n}\n", "key=value\n\n\n# end", "a=1\n}\n", "a { b=1\n",
	};
	for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
		blen = strlen(corpus[i]); memcpy(buf, corpus[i], blen + 1);
		char tag[32]; snprintf(tag, sizeof tag, "corpus%zu", i); observe(tag);
	}
	/* boundary cases: texts of exactly XBC_DATA_MAX bytes (and one either side) ending in a value that starts on the terminator, key paths of exactly the
	 * length and depth limits, and a deep path followed by a long one (the length accounted while popping back) */
	for (int variant = 0; variant < 10; variant++) {
		blen = 0;
		if (variant < 4) {
			static const char *tail[] = { "x=", "x=1", "x=", "x=" }; static const int tot[] = { 32765, 32764, 32766, 32766 };
			put("#"); while (blen < (size_t)tot[variant] - 1) putc_('c'); putc_('\n'); put(tail[variant]);
		} else if (variant < 6) {	/* a path of 16 (or 17) words of 15 characters: exactly 256 bytes of key at the depth limit */
			int words = variant == 4 ? 16 : 17;
			for (int w = 0; w < words; w++) { put("abcdefghijklmno"); put(w < words - 1 ? "." : " = 1\n"); }
		} else if (variant < 8) {	/* 16 one-letter words, then a path of 5 x 48 characters (245 bytes) or 6 x 48 */
			for (int w = 0; w < 16; w++) { putc_('a' + w); put(w < 15 ? "." : "=1\n"); }
			for (int w = 0; w < (variant == 6 ? 5 : 6); w++) { for (int c = 0; c < 48; c++) putc_('k'); put(w < (variant == 6 ? 4 : 5) ? "." : "=2\n"); }
		} else {	/* one key path of 255 bytes at depth 1 (a 254-character word) and one of 256 */
			for (int c = 0; c < (variant == 8 ? 254 : 255); c++) putc_('z'); put("=1\n");
		}
		buf[blen] = 0;
		char tag[32]; snprintf(tag, sizeof tag, "bound%d", variant); observe(tag);
	}
	for (long i = 0; i < n; i++) {
		gen_text();
		alloc_fail_in = rnd(25) == 0 ? 1 + rnd(2) : 0;
		char tag[32]; snprintf(tag, sizeof tag, "case%ld", i);
		observe(tag);
		alloc_fail_in = 0;
		if (live_allocs != 0) { printf("LEAK %ld\n", live_allocs); live_allocs = 0; }
	}
#ifdef ARM_RS
	if (getenv("BCF_PROVE")) printf("poison\n");
#endif
	return 0;
}
