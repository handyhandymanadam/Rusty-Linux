/* SPDX-License-Identifier: GPL-2.0 */
/* lib/nlattr.c: pristine C (c_*) vs the CONFIG_RUST=y code (rs_*: nlattr_glue.c's thunks and helpers over nlattr_rs.rs).
 * Random attribute streams (well formed, with bad lengths, trailing bytes and nested sub-streams) are parsed and validated against random
 * policies (every NLA_* type, every validation type, nested and recursive policies, range pointers, validate callbacks, strict_start_type)
 * with random validation flags. Compared for every call: the return value, the tb[] array, every field the extack was given (message text,
 * bad attribute, policy entry), the number of WARN/BUG events and the text of every trace / rate-limited message. Also the read-only
 * helpers: nla_policy_len, nla_find, nla_strscpy (also > 65535), nla_strdup, nla_memcpy, nla_memcmp, nla_strcmp, nla_get_range_*.
 * usage: main SHARD ; NL_N ; NL_PROVE_CAN_FAIL=1 */
#include "kshim.h"
#include <stdarg.h>

int ev_warn, ev_bug;
static char evbuf[16384]; static size_t evlen;
void ev_log(const char *fmt, ...)
{
	va_list ap; va_start(ap, fmt);
	if (evlen < sizeof evbuf - 256) evlen += vsnprintf(evbuf + evlen, 256, fmt, ap);
	va_end(ap);
	if (evlen < sizeof evbuf - 1) evbuf[evlen++] = '\n';
	evbuf[evlen] = 0;
}
void do_trace_netlink_extack(const char *msg) { ev_log("trace: %s", msg); }
static struct task_comm cur = { "tester" };
struct task_comm *current = &cur;

#define D(r, n, a) r c_##n a; r rs_##n a;
D(void, nla_get_range_unsigned, (const struct nla_policy *, struct netlink_range_validation *))
D(void, nla_get_range_signed, (const struct nla_policy *, struct netlink_range_validation_signed *))
D(int, __nla_validate, (const struct nlattr *, int, int, const struct nla_policy *, unsigned int, struct netlink_ext_ack *))
D(int, nla_policy_len, (const struct nla_policy *, int))
D(int, __nla_parse, (struct nlattr **, int, const struct nlattr *, int, const struct nla_policy *, unsigned int, struct netlink_ext_ack *))
D(struct nlattr *, nla_find, (const struct nlattr *, int, int))
D(ssize_t, nla_strscpy, (char *, const struct nlattr *, size_t))
D(char *, nla_strdup, (const struct nlattr *, gfp_t))
D(int, nla_memcmp, (const struct nlattr *, const void *, size_t))
D(int, nla_strcmp, (const struct nlattr *, const char *))
D(int, nla_memcpy, (void *, const struct nlattr *, int))

static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (fails++ < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }
static uint64_t rs_state;
static unsigned R(void) { return (unsigned)mix(rs_state += 1); }

/* ---- policies ---- */
#define NPOL 4
#define PSZ 8
static struct nla_policy pool[NPOL][PSZ];
static struct netlink_range_validation rng_u[3] = { { 0, 10 }, { 5, 5 }, { 100, 70000 } };
static struct netlink_range_validation_signed rng_s[3] = { { -5, 5 }, { -100000, 100000 }, { 0, 0 } };
static int cb0(const struct nlattr *a, struct netlink_ext_ack *e) { return nla_len(a) > 6 ? -EINVAL : 0; }
static int cb1(const struct nlattr *a, struct netlink_ext_ack *e) { return nla_len(a) >= 1 ? ((int8_t)((char *)nla_data(a))[0] < 0 ? -ERANGE : 0) : 5; }
static int (*cbs[2])(const struct nlattr *, struct netlink_ext_ack *) = { cb0, cb1 };
static const char *const rejects[] = { "rejected: not supported", "no" };

static void rand_entry(struct nla_policy *e, int idx)
{
	memset(e, 0, sizeof *e);
	e->type = R() % 22;
	e->validation_type = R() % 8;
	e->len = R() % 3 == 0 ? 0 : R() % 20;
	switch (e->type) {
	case NLA_NESTED: case NLA_NESTED_ARRAY:
		e->nested_policy = R() % 5 ? pool[R() % NPOL] : NULL; e->len = R() % PSZ; e->validation_type = NLA_VALIDATE_NONE; return;
	case NLA_REJECT:
		e->reject_message = R() % 2 ? rejects[R() % 2] : NULL; e->validation_type = NLA_VALIDATE_NONE; return;
	case NLA_BITFIELD32:
		*(u32 *)&e->bitfield32_valid = R() % 4 ? R() % 16 : 0; e->validation_type = NLA_VALIDATE_NONE; return;
	}
	switch (e->validation_type) {
	case NLA_VALIDATE_RANGE: case NLA_VALIDATE_RANGE_WARN_TOO_LONG: case NLA_VALIDATE_MIN: case NLA_VALIDATE_MAX: {
		int a = (int)(R() % 60) - 10, b = (int)(R() % 60) - 10; if (R() % 3) { if (a > b) { int t = a; a = b; b = t; } }
		e->min = a; e->max = b; break; }
	case NLA_VALIDATE_MASK: *(u32 *)&e->mask = R() % 3 ? (R() & 0xff) : R(); break;
	case NLA_VALIDATE_RANGE_PTR: if (R() % 2) e->range = &rng_u[R() % 3]; else e->range_signed = &rng_s[R() % 3]; break;
	case NLA_VALIDATE_FUNCTION: e->validate = R() % 5 ? cbs[R() % 2] : NULL; break;
	}
	if (idx == 0 && R() % 4 == 0 && e->validation_type == NLA_VALIDATE_NONE) e->strict_start_type = 1 + R() % 8;
}
static void rand_pool(void)
{
	for (int p = 0; p < NPOL; p++) for (int i = 0; i < PSZ; i++) rand_entry(&pool[p][i], i);
}

/* ---- streams ---- */
static int gen_stream(unsigned char *b, int depth, int maxtype)
{
	int n = 0, na = R() % 7;
	for (int a = 0; a < na; a++) {
		struct nlattr *at = (struct nlattr *)(b + n);
		int type = R() % (maxtype + 3), plen;
		unsigned sel = R() % 8;
		plen = sel < 3 ? R() % 12 : sel == 3 ? 1 << (R() % 4) : sel == 4 ? 8 + R() % 3 : R() % 30;
		unsigned char *pl = b + n + 4;
		if (depth < 3 && R() % 4 == 0) plen = gen_stream(pl, depth + 1, R() % PSZ);
		else for (int i = 0; i < plen; i++) { unsigned k = R() % 6; pl[i] = k == 0 ? 0 : k == 1 ? 1 : k == 2 ? 0xff : k == 3 ? 'a' + R() % 3 : (unsigned char)R(); }
		at->nla_type = type | (R() % 4 == 0 ? NLA_F_NESTED : 0) | (R() % 12 == 0 ? NLA_F_NET_BYTEORDER : 0);
		at->nla_len = 4 + plen;
		if (R() % 40 == 0) at->nla_len = R() % 6;                 /* too short */
		else if (R() % 40 == 0) at->nla_len = 4 + plen + 1 + R() % 8;   /* too long: claims bytes that are not there / belong to the next */
		n += NLA_ALIGN(4 + plen);
		memset(b + n - (NLA_ALIGN(4 + plen) - (4 + plen)), 0, NLA_ALIGN(4 + plen) - (4 + plen));
	}
	return n;
}

static long off_of(const void *p, const unsigned char *base) { return p ? (long)((const unsigned char *)p - base) : -1; }
static long pol_idx(const struct nla_policy *p) { return p ? (long)(p - &pool[0][0]) : -1; }

struct res { int rc; long tb[PSZ + 3]; char msg[96]; long bad, pol; int warn; char ev[2048]; };
static void arm_run(int rs, int fn, const unsigned char *buf, int len, int maxtype, const struct nla_policy *pol, unsigned flags,
		    int have_extack, struct res *o)
{
	struct nlattr *tb[PSZ + 3]; struct netlink_ext_ack ea;
	memset(&ea, 0, sizeof ea); ea.bad_attr = (void *)0x1; ea.policy = (void *)0x2; ea._msg = NULL;
	for (int i = 0; i < PSZ + 3; i++) tb[i] = (void *)0x77;
	ev_warn = 0; evlen = 0; evbuf[0] = 0;
	struct netlink_ext_ack *x = have_extack ? &ea : NULL;
	if (fn == 0) o->rc = rs ? rs___nla_parse(tb, maxtype, (const struct nlattr *)buf, len, pol, flags, x)
				: c___nla_parse(tb, maxtype, (const struct nlattr *)buf, len, pol, flags, x);
	else o->rc = rs ? rs___nla_validate((const struct nlattr *)buf, len, maxtype, pol, flags, x)
			: c___nla_validate((const struct nlattr *)buf, len, maxtype, pol, flags, x);
	for (int i = 0; i < PSZ + 3; i++) o->tb[i] = (fn == 0 && i <= maxtype) ? (tb[i] == (void *)0x77 ? -2 : off_of(tb[i], buf)) : 0;
	snprintf(o->msg, sizeof o->msg, "%s", ea._msg ? ea._msg : "(null)");
	o->bad = ea.bad_attr == (void *)0x1 ? -9 : off_of(ea.bad_attr, buf);
	o->pol = ea.policy == (void *)0x2 ? -9 : pol_idx(ea.policy);
	o->warn = ev_warn; snprintf(o->ev, sizeof o->ev, "%s", evbuf);
}
static char hmsg[64][96]; static long hcnt[64]; static long hrc0, hrcneg, hwarn, hev;
static void hist(const struct res *a)
{
	if (a->rc == 0) hrc0++; else hrcneg++;
	if (a->warn) hwarn++;
	if (a->ev[0]) hev++;
	for (int i = 0; i < 64; i++) {
		if (!hcnt[i]) { snprintf(hmsg[i], 96, "%s rc=%d", a->msg, a->rc); hcnt[i] = 1; return; }
		char t[96]; snprintf(t, 96, "%s rc=%d", a->msg, a->rc);
		if (!strcmp(hmsg[i], t)) { hcnt[i]++; return; }
	}
}
static int same(const struct res *a, const struct res *b)
{
	hist(a);
	return a->rc == b->rc && !memcmp(a->tb, b->tb, sizeof a->tb) && !strcmp(a->msg, b->msg) && a->bad == b->bad && a->pol == b->pol &&
	       a->warn == b->warn && !strcmp(a->ev, b->ev);
}

/* a chain of NESTED attributes `levels` deep against a policy that nests into itself: exercises the recursion limit */
static struct nla_policy selfpol[2];
static void deep_case(int levels)
{
	selfpol[0].type = NLA_UNSPEC; selfpol[1].type = NLA_NESTED; selfpol[1].len = 1; selfpol[1].nested_policy = selfpol;
	unsigned char *buf = calloc(1, 4 * levels + 64); int cur_len = 0;
	for (int l = 0; l < levels; l++) {          /* build from the inside out: each level wraps the previous one */
		memmove(buf + 4, buf, cur_len);
		struct nlattr *a = (struct nlattr *)buf; a->nla_len = 4 + cur_len; a->nla_type = 1 | NLA_F_NESTED; cur_len += 4;
	}
	for (unsigned flags = 0; flags < 32; flags += 7)
		for (int fn = 0; fn < 2; fn++) {
			struct res a, b; arm_run(0, fn, buf, cur_len, 1, selfpol, flags, 1, &a); arm_run(1, fn, buf, cur_len, 1, selfpol, flags, 1, &b);
			checks++;
			if (!same(&a, &b)) FAIL("deep MISMATCH levels=%d flags=%u rc %d/%d msg '%s'/'%s'\n", levels, flags, a.rc, b.rc, a.msg, b.msg);
		}
	free(buf);
}

/* every numeric type x every validation x payload lengths x boundary values, one attribute against policy[1] */
static void numeric_sweep(void)
{
	static const int types[] = { NLA_U8, NLA_U16, NLA_U32, NLA_U64, NLA_UINT, NLA_MSECS, NLA_BINARY, NLA_BE16, NLA_BE32, NLA_S8, NLA_S16, NLA_S32, NLA_S64, NLA_SINT, NLA_BITFIELD32 };
	static const int lens[] = { 0, 1, 2, 3, 4, 8, 9 };
	static const uint64_t vals[] = { 0, 1, 5, 10, 11, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffff, 0x80000000ULL, 0xffffffffULL, 0x100000000ULL, 0x8000000000000000ULL, ~0ULL, 0xfffffffffffffffbULL };
	static const int mm[][2] = { { 0, 10 }, { -5, 5 }, { 100, 200 }, { 0, 0 }, { 3, -3 }, { -128, 127 } };
	struct nla_policy pol[2];
	for (size_t ti = 0; ti < sizeof types / sizeof *types; ti++)
	for (int vt = 0; vt < 8; vt++)
	for (size_t mi = 0; mi < 6; mi++) {
		memset(pol, 0, sizeof pol);
		pol[1].type = types[ti]; pol[1].validation_type = vt; pol[1].len = (mi == 5) ? 3 : 0;
		if (types[ti] == NLA_BITFIELD32) { *(u32 *)&pol[1].bitfield32_valid = mi < 3 ? 0xf : 0; pol[1].validation_type = 0; }
		else if (vt == NLA_VALIDATE_MASK) *(u32 *)&pol[1].mask = mi == 0 ? 0xff : mi == 1 ? 0xf : mi == 2 ? 0xffff : mi == 3 ? 0 : 0xffffffff;
		else if (vt == NLA_VALIDATE_RANGE_PTR) { if (mi & 1) pol[1].range = &rng_u[mi % 3]; else pol[1].range_signed = &rng_s[mi % 3]; }
		else if (vt == NLA_VALIDATE_FUNCTION) pol[1].validate = mi % 3 == 2 ? NULL : cbs[mi & 1];
		else { pol[1].min = mm[mi][0]; pol[1].max = mm[mi][1]; }
		for (size_t li = 0; li < sizeof lens / sizeof *lens; li++)
		for (size_t vi = 0; vi < sizeof vals / sizeof *vals; vi++) {
			unsigned char buf[64] = { 0 }; struct nlattr *a = (struct nlattr *)buf;
			int plen = lens[li];
			if (types[ti] == NLA_BITFIELD32) { plen = 8; u32 v = (u32)vals[vi] & 0x1f, s = (u32)(vals[vi] >> 3) & 0x1f; memcpy(buf + 4, &v, 4); memcpy(buf + 8, &s, 4); }
			else memcpy(buf + 4, &vals[vi], plen < 8 ? plen : 8);
			a->nla_len = 4 + plen; a->nla_type = 1;
			for (unsigned fl = 0; fl < 32; fl += 8)
			for (int fn = 0; fn < 2; fn++) {
				struct res x, y; arm_run(0, fn, buf, NLA_ALIGN(4 + plen), 1, pol, fl, 1, &x); arm_run(1, fn, buf, NLA_ALIGN(4 + plen), 1, pol, fl, 1, &y);
				checks++;
				if (!same(&x, &y)) FAIL("numeric MISMATCH type=%d vt=%d mi=%zu len=%d val=%llx fl=%u rc %d/%d msg '%s'/'%s'\n", types[ti], vt, mi, plen, (unsigned long long)vals[vi], fl, x.rc, y.rc, x.msg, y.msg);
			}
		}
	}
}

static void diff(unsigned shard, long long n)
{
	rs_state = 0x7654321ULL * (shard + 1);
	rand_pool();
	if (shard == 0) numeric_sweep();
	for (long long it = 0; it < n; it++) {
		if (it % 64 == 0) rand_pool();
		if (it % 200 == 0) deep_case(8 + R() % 6);
		unsigned char *buf = calloc(1, 2048);
		int maxtype = R() % PSZ;
		int len = gen_stream(buf, 0, maxtype);
		if (R() % 8 == 0) { int extra = 1 + R() % 7; for (int i = 0; i < extra; i++) buf[len + i] = (unsigned char)R(); len += extra; }
		if (R() % 16 == 0 && len > 0) len -= 1 + R() % (len < 6 ? len : 6);
		const struct nla_policy *pol = R() % 8 ? pool[R() % NPOL] : NULL;
		unsigned flags = R() % 3 == 0 ? NL_VALIDATE_STRICT : R() % 32;
		int have = R() % 8 != 0;
		for (int fn = 0; fn < 2; fn++) {
			struct res a, b; arm_run(0, fn, buf, len, maxtype, pol, flags, have, &a); arm_run(1, fn, buf, len, maxtype, pol, flags, have, &b);
			if (poison && it == 9 && fn == 0) b.rc++;
			checks++;
			if (!same(&a, &b)) FAIL("MISMATCH fn=%d maxtype=%d len=%d flags=%u have=%d: rc %d/%d msg '%s'/'%s' bad %ld/%ld pol %ld/%ld warn %d/%d ev '%s' / '%s'\n",
						fn, maxtype, len, flags, have, a.rc, b.rc, a.msg, b.msg, a.bad, b.bad, a.pol, b.pol, a.warn, b.warn, a.ev, b.ev);
		}
		/* helpers on the first attribute, if there is one */
		const struct nlattr *at = (const struct nlattr *)buf;
		if (nla_ok(at, len)) {
			int ft = R() % (maxtype + 3);
			checks++;
			if (off_of(c_nla_find(at, len, ft), buf) != off_of(rs_nla_find(at, len, ft), buf)) FAIL("nla_find MISMATCH\n");
			/* strscpy / strdup / memcpy / memcmp / strcmp */
			static const size_t sizes[] = { 0, 1, 2, 3, 5, 9, 16, 70000 };
			size_t ds = sizes[R() % 8]; char *d1 = malloc(ds + 16), *d2 = malloc(ds + 16);
			memset(d1, 0xAA, ds + 16); memset(d2, 0xAA, ds + 16);
			ev_warn = 0; ssize_t r1 = c_nla_strscpy(d1, at, ds); int w1 = ev_warn; ev_warn = 0; ssize_t r2 = rs_nla_strscpy(d2, at, ds); int w2 = ev_warn;
			checks++;
			if (r1 != r2 || w1 != w2 || memcmp(d1, d2, ds + 16)) FAIL("nla_strscpy MISMATCH ds=%zu: %zd/%zd warn %d/%d\n", ds, r1, r2, w1, w2);
			free(d1); free(d2);
			char *s1 = c_nla_strdup(at, 0), *s2 = rs_nla_strdup(at, 0);
			checks++;
			if (!s1 != !s2 || (s1 && strcmp(s1, s2))) FAIL("nla_strdup MISMATCH\n");
			free(s1); free(s2);
			int cnt = R() % 30; unsigned char m1[48], m2[48]; memset(m1, 0xAA, 48); memset(m2, 0xAA, 48);
			int q1 = c_nla_memcpy(m1, at, cnt), q2 = rs_nla_memcpy(m2, at, cnt);
			checks++;
			if (q1 != q2 || memcmp(m1, m2, 48)) FAIL("nla_memcpy MISMATCH cnt=%d\n", cnt);
			unsigned char dat[32]; for (int i = 0; i < 32; i++) dat[i] = R() % 3 ? ((unsigned char *)nla_data(at))[i % (nla_len(at) > 0 ? nla_len(at) : 1)] : (unsigned char)R();
			size_t sz = R() % 20; int e1 = c_nla_memcmp(at, dat, sz), e2 = rs_nla_memcmp(at, dat, sz);
			checks++;
			if ((e1 > 0) != (e2 > 0) || (e1 < 0) != (e2 < 0)) FAIL("nla_memcmp MISMATCH %d/%d\n", e1, e2);
			char str[24]; for (int i = 0; i < 23; i++) str[i] = R() % 4 ? ((char *)nla_data(at))[i % (nla_len(at) > 0 ? nla_len(at) : 1)] : 'a' + R() % 3;
			str[R() % 23] = 0; str[23] = 0;
			int g1 = c_nla_strcmp(at, str), g2 = rs_nla_strcmp(at, str);
			checks++;
			if ((g1 > 0) != (g2 > 0) || (g1 < 0) != (g2 < 0)) FAIL("nla_strcmp MISMATCH %d/%d\n", g1, g2);
		}
		/* policy_len and the range getters */
		int pn = 1 + R() % PSZ; const struct nla_policy *pp = pool[R() % NPOL];
		checks++;
		if (c_nla_policy_len(pp, pn) != rs_nla_policy_len(pp, pn)) FAIL("nla_policy_len MISMATCH\n");
		struct nla_policy e; rand_entry(&e, 1);
		if (e.validation_type == NLA_VALIDATE_RANGE_PTR || e.type < NLA_NESTED || e.type == NLA_BINARY) {
			struct netlink_range_validation u1, u2; struct netlink_range_validation_signed s1, s2;
			memset(&u1, 0xAA, sizeof u1); memset(&u2, 0xAA, sizeof u2); memset(&s1, 0xAA, sizeof s1); memset(&s2, 0xAA, sizeof s2);
			ev_warn = 0; c_nla_get_range_unsigned(&e, &u1); int wu1 = ev_warn; ev_warn = 0; rs_nla_get_range_unsigned(&e, &u2); int wu2 = ev_warn;
			ev_warn = 0; c_nla_get_range_signed(&e, &s1); int ws1 = ev_warn; ev_warn = 0; rs_nla_get_range_signed(&e, &s2); int ws2 = ev_warn;
			checks++;
			if (memcmp(&u1, &u2, sizeof u1) || memcmp(&s1, &s2, sizeof s1) || wu1 != wu2 || ws1 != ws2) FAIL("nla_get_range MISMATCH type=%d vt=%d\n", e.type, e.validation_type);
		}
		free(buf);
	}
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("NL_PROVE_CAN_FAIL") != 0;
	diff(shard, getenv("NL_N") ? atoll(getenv("NL_N")) : 400000LL);
	if (getenv("NL_STATS")) { printf("rc==0 %ld, rc<0 %ld, with WARN %ld, with trace/pr events %ld\n", hrc0, hrcneg, hwarn, hev); for (int i = 0; i < 64 && hcnt[i]; i++) printf("  %6ld  %s\n", hcnt[i], hmsg[i]); }
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
