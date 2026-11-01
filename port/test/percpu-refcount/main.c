/* percpu-refcount differential: the same op stream drives pristine lib/percpu-refcount.c (ARM_REF) or percpu-refcount_glue.c over percpu_refcount_rs.rs (ARM_RS).
 * Three refs with random init flags; gets / puts on random "CPUs", tryget / tryget_live, kill, switch to atomic (with and without confirm, sync), switch to percpu,
 * reinit, resurrect, grace periods (the queued RCU callbacks run when the test says so, or when a wait_event needs them), is_zero, exit, allocation failure in init.
 * After every op the whole state is printed.  usage: t SHARD (env PR_N, PR_PROVE=1) */
#include "kshim.h"
#include SRC

int warn_count, shim_cpu, alloc_fail_in; bool warn_site[64]; long live_allocs, wakes, waits;

/* ---- the RCU callback queue ---- */
static struct rcu_head *q_head, *q_tail; static long q_len, q_ran;
void call_rcu_hurry(struct rcu_head *head, rcu_callback_t func) { head->func = func; head->next = NULL; if (q_tail) q_tail->next = head; else q_head = head; q_tail = head; q_len++; }
bool rcu_run_one(void)
{
	struct rcu_head *h = q_head;
	if (!h) return false;
	q_head = h->next; if (!q_head) q_tail = NULL; q_len--; q_ran++;
	h->func(h);
	return true;
}
void rcu_run(void) { while (rcu_run_one()) ; }

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 33) % n : 0; }

#define NR 3
static struct percpu_ref refs[NR]; static bool inited[NR], exited[NR]; static long held[NR];
static int rel_n[NR], conf_n[NR];
static int idx_of(struct percpu_ref *r) { return (int)(r - refs); }
static void release_fn(struct percpu_ref *r) { rel_n[idx_of(r)]++; }
static void confirm_fn(struct percpu_ref *r) { conf_n[idx_of(r)]++; }

static void state(void)
{
	for (int i = 0; i < NR; i++) {
		struct percpu_ref *r = &refs[i];
		if (!inited[i]) { printf("  r%d -\n", i); continue; }
		unsigned long pc = r->percpu_count_ptr & ~3UL; long sum = 0;
		if (!exited[i] && pc) for (int c = 0; c < NSHIM_CPUS; c++) sum += (long)((unsigned long *)pc)[c];
		printf("  r%d ex=%d flags=%lu pc=%d data=%d", i, exited[i], r->percpu_count_ptr & 3, pc != 0, r->data != NULL);
		if (r->data) printf(" count=%ld conf=%d force=%d reinit=%d", atomic_long_read(&r->data->count), r->data->confirm_switch != NULL, r->data->force_atomic, r->data->allow_reinit);
		else printf(" packed=%lu", r->percpu_count_ptr >> 2);
		printf(" sum=%ld rel=%d confirm=%d\n", sum, rel_n[i], conf_n[i]);
	}
	printf("  Q pending=%ld ran=%ld wakes=%ld waits=%ld warn=%d live=%ld\n", q_len, q_ran, wakes, waits, warn_count, live_allocs);
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("PR_N") ? atol(getenv("PR_N")) : 20000;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long step = 0; step < n; step++) {
		int i = rnd(NR); struct percpu_ref *r = &refs[i]; unsigned op = rnd(100); shim_cpu = rnd(NSHIM_CPUS);
		if (step % 3000 == 2999) memset(warn_site, 0, sizeof(warn_site));
		if (exited[i] && rnd(3) == 0) {	/* a ref between exit and the next init: only is_zero is allowed, and it reads the count packed into percpu_count_ptr */
			printf("is_zero_after_exit r%d -> %d\n", i, percpu_ref_is_zero(r)); state(); continue;
		}
		if (!inited[i] || exited[i]) {
			static const unsigned fl[] = { 0, 0, 0, 1, 2, 4, 5, 6, 7, 3, 4, 4 };
			unsigned f = fl[rnd(12)]; alloc_fail_in = rnd(8) == 0 ? 1 + rnd(2) : 0;
			int rc = percpu_ref_init(r, release_fn, f, GFP_KERNEL); alloc_fail_in = 0;
			printf("init r%d flags=%u -> %d\n", i, f, rc);
			if (rc == 0) { inited[i] = true; exited[i] = false; held[i] = (f & 2) ? 0 : 1; rel_n[i] = conf_n[i] = 0; }
			else { inited[i] = false; if (r->percpu_count_ptr || r->data) printf("  LEFTOVER\n"); }
			state(); continue;
		}
		bool can_reuse = r->data && r->data->allow_reinit && (r->percpu_count_ptr & ~3UL);
		if (op < 12 && held[i] > 0) { percpu_ref_get(r); held[i]++; printf("get r%d cpu=%d\n", i, shim_cpu); }
		else if (op < 16 && held[i] > 0) { unsigned long k = 1 + rnd(3); percpu_ref_get_many(r, k); held[i] += k; printf("get_many r%d %lu\n", i, k); }
		else if (op < 22) { bool t = percpu_ref_tryget(r); if (t) held[i]++; printf("tryget r%d -> %d\n", i, t); }
		else if (op < 30) { bool t = percpu_ref_tryget_live(r); if (t) held[i]++; printf("tryget_live r%d -> %d\n", i, t); }
		else if (op < 55 && held[i] > 0) { percpu_ref_put(r); held[i]--; printf("put r%d cpu=%d\n", i, shim_cpu); }
		else if (op < 60 && held[i] > 1) { unsigned long k = 1 + rnd(held[i] < 3 ? held[i] : 3); percpu_ref_put_many(r, k); held[i] -= k; printf("put_many r%d %lu\n", i, k); }
		else if (op < 68 && held[i] > 0 && !percpu_ref_is_dying(r)) { bool cf = rnd(2); percpu_ref_kill_and_confirm(r, cf ? confirm_fn : NULL); held[i]--; printf("kill r%d confirm=%d\n", i, cf); }
		else if (op < 72 && (r->percpu_count_ptr & ~3UL)) { bool cf = rnd(2); percpu_ref_switch_to_atomic(r, cf ? confirm_fn : NULL); printf("to_atomic r%d confirm=%d\n", i, cf); }
		else if (op < 75 && (r->percpu_count_ptr & ~3UL)) { percpu_ref_switch_to_atomic_sync(r); printf("to_atomic_sync r%d\n", i); }
		else if (op < 79 && (r->percpu_count_ptr & ~3UL)) { percpu_ref_switch_to_percpu(r); printf("to_percpu r%d\n", i); }
		else if (op < 83 && can_reuse && percpu_ref_is_dying(r) && percpu_ref_is_zero(r)) { percpu_ref_reinit(r); held[i] = 1; printf("reinit r%d\n", i); }
		else if (op < 87 && can_reuse && percpu_ref_is_dying(r) && held[i] == 0) { percpu_ref_resurrect(r); held[i] = 1; printf("resurrect r%d\n", i); }
		else if (op < 94) { int k = rnd(3) ? 1 : 100; long b = q_ran; while (k-- && rcu_run_one()) ; printf("grace r%d ran=%ld\n", i, q_ran - b); }
		else if (op < 97) { printf("is_zero r%d -> %d\n", i, percpu_ref_is_zero(r)); }
		else if (op == 97 && held[i] > 0 && percpu_ref_is_dying(r)) { percpu_ref_kill_and_confirm(r, NULL); held[i]--; printf("kill_again r%d\n", i); }	/* WARNs */
		else if (op == 98 && can_reuse && percpu_ref_is_dying(r) && !percpu_ref_is_zero(r)) { percpu_ref_reinit(r); held[i]++; printf("reinit_nonzero r%d\n", i); }	/* WARNs */
		else {
			/* exit only when nothing is in flight and the ref is dead and drained */
			rcu_run();
			if (percpu_ref_is_dying(r) && held[i] == 0) { percpu_ref_exit(r); exited[i] = true; printf("exit r%d\n", i); }
			else if (rnd(3) == 0) { percpu_ref_exit(r); exited[i] = true; printf("exit_busy r%d held=%ld\n", i, held[i]); }	/* init-failure style: still holding references */
			else printf("nop\n");
		}
		state();
	}
	rcu_run();
	for (int i = 0; i < NR; i++) if (inited[i] && !exited[i]) { if (!percpu_ref_is_dying(&refs[i])) { percpu_ref_kill(&refs[i]); } }
	rcu_run();
	state();
#ifdef ARM_RS
	if (getenv("PR_PROVE")) printf("poison\n");
#endif
	return 0;
}
