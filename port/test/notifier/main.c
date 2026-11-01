/* notifier chain differential: the pristine chain core (ARM_REF: ref.c) against notifier_rs.rs plus the wrappers of notifier_glue.c (ARM_RS). A pool of 12 notifier blocks with
 * random priorities (many ties) and scripted callbacks (each returns a value that depends on its id and the action, sometimes with NOTIFY_STOP_MASK, and logs its call); random
 * register / unique register / unregister / call / call with a count / robust call; prints every result, the chain order and the call log.   usage: t SHARD (env NT_N, NT_PROVE) */
#include "refshim.h"
int warns, traces_reg, traces_unreg, traces_run;
#define NB 12
static struct notifier_block nbs[NB];
static char calllog[4096]; static int logn;
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
static unsigned stop_mod[NB], ret_mod[NB];
static struct notifier_block *g_head;
static int cb(struct notifier_block *nb, unsigned long action, void *data);
static int cb_bad(struct notifier_block *nb, unsigned long action, void *data) { return cb(nb, action, data); }
int t_is_text(notifier_fn_t f) { return f != cb_bad; }
#ifdef ARM_REF
#include "ref.c"
#define T_REG ref_register
#define T_UNREG ref_unregister
#define T_CALL ref_call
#define T_ROBUST ref_robust
#else
int rust_nt_register(struct notifier_block **, struct notifier_block *, bool); int rust_nt_unregister(struct notifier_block **, struct notifier_block *);
int rust_nt_call_chain(struct notifier_block **, unsigned long, void *, int, int *); int rust_nt_call_chain_robust(struct notifier_block **, unsigned long, unsigned long, void *);
/* the wrappers of notifier_glue.c */
void rust_nt_warn_dup(struct notifier_block *n) { warns++; }
void rust_nt_trace_register(struct notifier_block *n) { traces_reg++; }
void rust_nt_trace_unregister(struct notifier_block *n) { traces_unreg++; }
int rust_nt_call(struct notifier_block *nb, unsigned long val, void *v) { traces_run++; return nb->notifier_call(nb, val, v); }
bool rust_nt_callback_ok(struct notifier_block *nb) { if (!t_is_text(nb->notifier_call)) { warns++; return false; } return true; }
#define T_REG rust_nt_register
#define T_UNREG rust_nt_unregister
#define T_CALL rust_nt_call_chain
#define T_ROBUST rust_nt_call_chain_robust
#endif
static int cb(struct notifier_block *nb, unsigned long action, void *data)
{
	int id = (int)(nb - nbs);
	logn += snprintf(calllog + logn, sizeof calllog - logn, "%d/%lu ", id, action);
	if (id % 4 == 3 && action == 5) { T_UNREG(&g_head, nb); nb->priority += 1; T_REG(&g_head, nb, 0); } /* a callback that moves itself in the chain it is being called from */
	int r = (int)((id * 7 + action * 3) % (ret_mod[id] + 1));
	if ((id + action) % stop_mod[id] == 0) r |= NOTIFY_STOP_MASK;
	return r;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("NT_N") ? atol(getenv("NT_N")) : 30000; int prove = getenv("NT_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long round = 0; round < n / 200; round++) {
		g_head = NULL;
		for (int i = 0; i < NB; i++) { nbs[i].notifier_call = (i % 5 == 4) ? cb_bad : cb; nbs[i].next = (void *)0x1; nbs[i].priority = (int)rnd(5) - 2; stop_mod[i] = 2 + rnd(6); ret_mod[i] = 1 + rnd(4); }
		for (int op = 0; op < 200; op++) {
			int k = (int)rnd(NB), r = 0, nc = -99; unsigned o = rnd(10); unsigned long act = rnd(7);
			logn = 0; calllog[0] = 0;
			printf("%ld.%d ", round, op);
			if (o < 3) { r = T_REG(&g_head, &nbs[k], 0); printf("reg %d prio=%d -> %d", k, nbs[k].priority, r); }
			else if (o < 4) { r = T_REG(&g_head, &nbs[k], 1); printf("regu %d prio=%d -> %d", k, nbs[k].priority, r); }
			else if (o < 6) { r = T_UNREG(&g_head, &nbs[k]); printf("unreg %d -> %d", k, r); }
			else if (o < 8) { r = T_CALL(&g_head, act, NULL, -1, rnd(2) ? &nc : NULL); printf("call %lu -> %#x nc=%d log=%s", act, r, nc, calllog); }
			else if (o < 9) { int cnt = (int)rnd(5); nc = 0; r = T_CALL(&g_head, act, NULL, cnt, &nc); printf("calln %lu cnt=%d -> %#x nc=%d log=%s", act, cnt, r, nc, calllog); }
			else { r = T_ROBUST(&g_head, act, act + 100, NULL); printf("robust %lu -> %#x log=%s", act, r, calllog); }
			printf(" | chain:"); for (struct notifier_block *p = g_head; p; p = p->next) printf(" %d", (int)(p - nbs));
			printf(" w=%d t=%d/%d/%d\n", warns, traces_reg, traces_unreg, traces_run);
		}
		if (prove && round == 0) printf("  POISON\n");
	}
	printf("final w=%d\n", warns);
	return 0;
}
