/* ucount counter-walk differential: pristine slice (ARM_REF: ref.c) against ucount_rs.rs plus the wrappers of ucount_glue.c (ARM_RS). A three-level namespace chain with small random
 * limits and counts; ops: inc_ucount / dec_ucount (with allocation failure), inc/dec_rlimit_ucounts, inc_rlimit_get / dec_rlimit_put (with get_ucounts failure), is_rlimit_overlimit,
 * starting at a random level, with negative and huge values. Prints every result, all counters, reference counts and warn counts.   usage: t SHARD (env UC_N, UC_PROVE) */
#include "refshim.h"
int warns;
static struct user_namespace ns[3]; static struct ucounts uc[3];
static int alloc_fail, get_fail, puts_, allocs_;
struct ucounts *alloc_ucounts(struct user_namespace *n, kuid_t uid) { if (alloc_fail) return NULL; allocs_++; uc[n - ns].refs++; return &uc[n - ns]; }
void put_ucounts(struct ucounts *u) { puts_++; u->refs--; }
struct ucounts *get_ucounts(struct ucounts *u) { if (get_fail) return NULL; u->refs++; return u; }
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
#ifdef ARM_REF
#include "ref.c"
#define T_INC inc_ucount
#define T_DEC dec_ucount
#define T_RINC inc_rlimit_ucounts
#define T_RDEC dec_rlimit_ucounts
#define T_RGET inc_rlimit_get_ucounts
#define T_RPUT dec_rlimit_put_ucounts
#define T_OVER is_rlimit_overlimit
#else
struct ucounts *rust_inc_ucount(struct user_namespace *, u32, int); void rust_dec_ucount(struct ucounts *, int);
long rust_inc_rlimit_ucounts(struct ucounts *, int, long); bool rust_dec_rlimit_ucounts(struct ucounts *, int, long);
void rust_dec_rlimit_put_ucounts(struct ucounts *, int); long rust_inc_rlimit_get_ucounts(struct ucounts *, int, bool); bool rust_is_rlimit_overlimit(struct ucounts *, int, u64);
const size_t rust_uc_off_ns = offsetof(struct ucounts, ns), rust_uc_off_ucount = offsetof(struct ucounts, ucount), rust_uc_off_rlimit = offsetof(struct ucounts, rlimit);
const size_t rust_uc_off_ns_ucounts = offsetof(struct user_namespace, ucounts), rust_uc_off_ns_ucount_max = offsetof(struct user_namespace, ucount_max), rust_uc_off_ns_rlimit_max = offsetof(struct user_namespace, rlimit_max);
struct ucounts *rust_uc_alloc(struct user_namespace *n, u32 uid) { kuid_t k = { uid }; return alloc_ucounts(n, k); }
void rust_uc_put(struct ucounts *u) { put_ucounts(u); }
struct ucounts *rust_uc_get(struct ucounts *u) { return get_ucounts(u); }
void rust_uc_warn_dec_ucount(void) { warns++; }
void rust_uc_warn_dec_rlimit(void) { warns++; }
void rust_uc_warn_do_dec(void) { warns++; }
void rust_uc_warn_unwind(void) { warns++; }
#define T_INC(n, uid, t) rust_inc_ucount(n, (uid).val, t)
#define T_DEC rust_dec_ucount
#define T_RINC rust_inc_rlimit_ucounts
#define T_RDEC rust_dec_rlimit_ucounts
#define T_RGET rust_inc_rlimit_get_ucounts
#define T_RPUT rust_dec_rlimit_put_ucounts
#define T_OVER rust_is_rlimit_overlimit
#endif
static void state(void)
{
	printf(" st:");
	for (int i = 0; i < 3; i++) { printf(" [r%d", uc[i].refs); for (int t = 0; t < NUC; t++) printf(" %ld", uc[i].ucount[t].counter); printf(" |"); for (int t = 0; t < NRL; t++) printf(" %ld", uc[i].rlimit[t].counter); printf("]"); }
	printf(" w=%d a=%d p=%d", warns, allocs_, puts_);
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("UC_N") ? atol(getenv("UC_N")) : 40000; int prove = getenv("UC_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long round = 0; round < n / 100; round++) {
		memset(ns, 0, sizeof ns); memset(uc, 0, sizeof uc);
		for (int i = 0; i < 3; i++) { uc[i].ns = &ns[i]; ns[i].ucounts = i ? &uc[i - 1] : NULL; uc[i].refs = 1;
			for (int t = 0; t < NUC; t++) { ns[i].ucount_max[t] = rnd(8) == 0 ? LONG_MAX : rnd(6); uc[i].ucount[t].counter = rnd(4); }
			for (int t = 0; t < NRL; t++) { ns[i].rlimit_max[t] = rnd(8) == 0 ? LONG_MAX : rnd(6); uc[i].rlimit[t].counter = rnd(10) == 0 ? -1 - (long)rnd(3) : rnd(4); } }
		for (int op = 0; op < 100; op++) {
			int lvl = rnd(3), t = rnd(NUC), rt = rnd(NRL); unsigned o = rnd(8); long v = rnd(6) == 0 ? (long)rnd(3) - 1 : rnd(5) == 0 ? LONG_MAX / 2 + rnd(3) : 1 + rnd(3);
			alloc_fail = rnd(10) == 0; get_fail = rnd(6) == 0; printf("%ld.%d ", round, op);
			if (o == 0) { kuid_t k = { 1000 }; struct ucounts *r = T_INC(&ns[lvl], k, t); printf("inc lvl %d t %d -> %d", lvl, t, r ? (int)(r - uc) : -1); }
			else if (o == 1) { T_DEC(&uc[lvl], t); printf("dec lvl %d t %d", lvl, t); }
			else if (o == 2) { long r = T_RINC(&uc[lvl], rt, v); printf("rinc lvl %d t %d v %ld -> %ld", lvl, rt, v, r); }
			else if (o == 3) { bool r = T_RDEC(rnd(10) == 0 ? NULL : &uc[lvl], rt, v); printf("rdec lvl %d t %d v %ld -> %d", lvl, rt, v, r); }
			else if (o <= 5) { bool ov = rnd(2); long r = T_RGET(&uc[lvl], rt, ov); printf("rget lvl %d t %d ov %d -> %ld", lvl, rt, ov, r); }
			else if (o == 6) { T_RPUT(&uc[lvl], rt); printf("rput lvl %d t %d", lvl, rt); }
			else { unsigned long lim = rnd(3) == 0 ? ~0UL - rnd(3) : rnd(6); bool r = T_OVER(&uc[lvl], rt, lim); printf("over lvl %d t %d lim %lx -> %d", lvl, rt, lim, r); }
			state(); printf("\n");
		}
		if (prove && round == 0) printf("  POISON\n");
	}
	printf("final w=%d\n", warns);
	return 0;
}
