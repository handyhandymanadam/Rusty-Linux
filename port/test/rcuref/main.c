/* port/test/rcuref/main.c -- differential driver for lib/rcuref.c: get / put (the header's inline logic, copied) over hostile counter values
 * with a racing get or put injected between a put's decrement and its slow path, original vs rcuref_glue.c + rcuref_rs.rs. One digest per case.
 * WARN_ONCE counts every firing (the "once" is not part of the observable here).   t <shard>; env RCU_N cases, RCU_PROVE=1 (Rust build only). */
#include <linux/rcuref.h>
int warn_count;
static uint64_t rs = 88172645463325252ULL;
static uint32_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return (uint32_t)(rs >> 16); }
static uint64_t dig;
static void mix(uint64_t v) { for (int k = 0; k < 8; k++) { dig ^= (v >> (k * 8)) & 0xff; dig *= 0x100000001b3ULL; } }
#ifdef ARM_RS
static int poison;
#endif
static bool do_get(rcuref_t *r)
{
	if (likely(!(__atomic_add_fetch(&r->refcnt.counter, 1, __ATOMIC_RELAXED) < 0))) return true;
	return rcuref_get_slowpath(r);
}
/* put with an optional interference between the decrement and the slow path */
static bool do_put(rcuref_t *r, unsigned race)
{
	int cnt = __atomic_sub_fetch(&r->refcnt.counter, 1, __ATOMIC_RELEASE);
	if (likely(cnt >= 0)) return false;
	if (race == 1) (void)do_get(r);          /* a get slips in: the cmpxchg to DEAD must fail */
	else if (race == 2) __atomic_sub_fetch(&r->refcnt.counter, 1, __ATOMIC_RELEASE);   /* another put slips in */
	return rcuref_put_slowpath(r, (unsigned)cnt);
}
static uint32_t start_value(void)
{
	static const uint32_t special[] = { 0, 1, 2, RCUREF_MAXREF, RCUREF_MAXREF - 1, RCUREF_MAXREF + 1, RCUREF_SATURATED - 1, RCUREF_SATURATED,
		RCUREF_SATURATED + 1, RCUREF_RELEASED - 1, RCUREF_RELEASED, RCUREF_RELEASED + 1, RCUREF_DEAD - 1, RCUREF_DEAD, RCUREF_DEAD + 1,
		RCUREF_NOREF - 1, RCUREF_NOREF };
	return rnd() % 3 ? special[rnd() % (sizeof(special) / sizeof(special[0]))] : rnd() % 8;
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0, ncase = getenv("RCU_N") ? (unsigned)atoi(getenv("RCU_N")) : 200000;
	for (unsigned n = 0; n < ncase; n++) {
		rs = 0x9e3779b97f4a7c15ULL * (shard * 1000003u + n + 1); for (int k = 0; k < 8; k++) rnd();
		dig = 0xcbf29ce484222325ULL; warn_count = 0;
		rcuref_t r; atomic_set(&r.refcnt, (int)start_value());
		for (unsigned o = 0, no = 1 + rnd() % 12; o < no; o++) {
			bool res = (rnd() & 1) ? do_get(&r) : do_put(&r, rnd() % 3 == 0 ? 1 + rnd() % 2 : 0);
#ifdef ARM_RS
			if (getenv("RCU_PROVE") && !poison++) res = !res;
#endif
			mix(res); mix((uint32_t)atomic_read(&r.refcnt)); mix(warn_count);
		}
		printf("%u.%u %016llx\n", shard, n, (unsigned long long)dig);
	}
	return 0;
}
