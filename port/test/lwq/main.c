/* lwq differential: the same op stream drives pristine lib/lwq.c (ARM_REF) or lwq_glue.c over lwq_rs.rs (ARM_RS); nodes carry ids so every result and the
 * whole queue state (ready chain, new chain, placeholder) print as id lists. Then a threaded phase: producers enqueue numbered items, consumers dequeue
 * with __lwq_dequeue and lwq_dequeue_all; every item must come out exactly once and each producer's items in order.  usage: t SHARD (env LQ_N, LQ_PROVE=1) */
#include "kshim.h"
#include SRC

struct llist_node *llist_reverse_order(struct llist_node *head)
{
	struct llist_node *new_head = NULL;
	while (head) { struct llist_node *tmp = head; head = head->next; tmp->next = new_head; new_head = tmp; }
	return new_head;
}

struct item { struct lwq_node n; int id; };
#define NI 64
static struct item items[NI]; static bool in_q[NI];
static u_int64_t rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 33) % n : 0; }
static int idof(struct llist_node *n) { return n == (void *)1 ? -2 : n ? ((struct item *)n)->id : -1; }
static void chain(const char *tag, struct llist_node *n) { printf(" %s:", tag); for (int k = 0; n && n != (void *)1 && k < 100; n = n->next, k++) printf("%d,", idof(n)); if (n == (void *)1) printf("PLACEHOLDER"); }

static struct lwq q;
static void state(void)
{
	printf("  S"); chain("ready", q.ready); chain("new", q.new.first); printf(" empty=%d\n", lwq_empty(&q));
}

static struct lwq tq; static int got[4][100000]; static int ngot[4]; enum { PER = 20000 };
static void *prod(void *a)
{
	long p = (long)a;
	struct item *it = calloc(PER, sizeof(*it));
	for (int i = 0; i < PER; i++) { it[i].id = p * 1000000 + i; lwq_enqueue(&it[i].n, &tq); }
	return NULL;
}
static int stop;
static void *cons(void *a)
{
	long c = (long)a; int total = 0;
	for (;;) {
		struct llist_node *n;
		if (c & 1) { n = lwq_dequeue_all(&tq); for (; n; n = n->next) { int id = ((struct item *)n)->id; got[c][ngot[c]++] = id; total++; } }
		else { n = __lwq_dequeue(&tq); if (n) { got[c][ngot[c]++] = ((struct item *)n)->id; total++; } }
		if (!n && __atomic_load_n(&stop, __ATOMIC_ACQUIRE) && lwq_empty(&tq)) break;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("LQ_N") ? atol(getenv("LQ_N")) : 20000;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	lwq_init(&q);
	for (int i = 0; i < NI; i++) items[i].id = i;
	state();
	for (long i = 0; i < n; i++) {
		unsigned op = rnd(10);
		if (op < 5) {
			int k = rnd(NI);
			if (!in_q[k]) { bool r = lwq_enqueue(&items[k].n, &q); in_q[k] = true; printf("enq %d -> %d\n", k, r); } else printf("enq skip\n");
		} else if (op < 8) {
			struct llist_node *r = __lwq_dequeue(&q);
			if (r) in_q[idof(r)] = false;
			printf("deq -> %d\n", idof(r));
		} else if (op < 9) {
			struct llist_node *r = lwq_dequeue_all(&q); printf("deqall ->");
			for (; r; r = r->next) { in_q[idof(r)] = false; printf(" %d", idof(r)); }
			printf("\n");
		} else printf("nop\n");
		state();
	}
	/* threaded phase */
	for (int round = 0; round < 6; round++) {
		pthread_t pt[4], ct[4]; int total = 0;
		lwq_init(&tq); stop = 0; memset(ngot, 0, sizeof(ngot));
		for (long c = 0; c < 4; c++) pthread_create(&ct[c], NULL, cons, (void *)c);
		for (long p = 0; p < 4; p++) pthread_create(&pt[p], NULL, prod, (void *)p);
		for (int p = 0; p < 4; p++) pthread_join(pt[p], NULL);
		__atomic_store_n(&stop, 1, __ATOMIC_RELEASE);
		for (int c = 0; c < 4; c++) pthread_join(ct[c], NULL);
		/* every item exactly once, and each consumer sees each producer's items in increasing order */
		static unsigned char seen[4][PER]; memset(seen, 0, sizeof(seen)); int dup = 0, ooo = 0;
		for (int c = 0; c < 4; c++) {
			int last[4] = { -1, -1, -1, -1 };
			for (int k = 0; k < ngot[c]; k++) {
				int id = got[c][k], p = id / 1000000, i = id % 1000000;
				if (seen[p][i]++) dup++;
				if (i < last[p]) ooo++;
				last[p] = i; total++;
			}
		}
		printf("threads round %d total=%d dup=%d out_of_order=%d empty=%d\n", round, total, dup, ooo, lwq_empty(&tq));
	}
#ifdef ARM_RS
	if (getenv("LQ_PROVE")) printf("poison\n");
#endif
	return 0;
}
