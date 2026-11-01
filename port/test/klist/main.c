/* klist differential: the same op stream drives pristine lib/klist.c (ARM_REF) or klist_glue.c over klist_rs.rs (ARM_RS). 12 nodes, 3 iterators, one klist with get/put callbacks.
 * Ops: add_head / add_tail / add_behind / add_before (pos may be a dead node still in the list), del, remove (only when it cannot block), node_attached, iter_init /
 * iter_init_node / next / prev / exit. After every op the list (order, refcount, dead bit per node), the iterators, the get/put counts and the warning count are printed.
 * Then a threaded phase: klist_remove() blocks while another thread's iterator holds the node and returns once it exits.  usage: t SHARD (env KL_N, KL_PROVE=1) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/sched.h>
long lock_ops; int warn_count; __thread struct task_struct *current;
#include <linux/klist.h>
#include SRC

#define NN 12
#define NI 3
struct tn { struct klist_node n; int id; };
static struct tn nodes[NN];
static struct klist k;
static struct klist_iter its[NI]; static int it_live[NI];
static int gets[NN], puts_[NN];
static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
static void kget(struct klist_node *n) { gets[((struct tn *)n)->id]++; }
static void kput(struct klist_node *n) { puts_[((struct tn *)n)->id]++; }
static int idof(struct klist_node *n) { return n ? ((struct tn *)n)->id : -1; }

static void state(void)
{
	struct list_head *p;
	printf("  S warn=%d list:", warn_count);
	for (p = k.k_list.next; p != &k.k_list; p = p->next) {
		struct klist_node *n = container_of(p, struct klist_node, n_node);
		printf(" %d(r%d%s)", idof(n), n->n_ref.refcount.refs, ((unsigned long)n->n_klist & 1) ? "D" : "");
	}
	printf(" iters:");
	for (int i = 0; i < NI; i++) printf(" %d", it_live[i] ? idof(its[i].i_cur) : -9);
	printf(" gets:"); for (int i = 0; i < NN; i++) printf("%d,", gets[i]);
	printf(" puts:"); for (int i = 0; i < NN; i++) printf("%d,", puts_[i]);
	printf("\n");
}
static int attached(int i) { return klist_node_attached(&nodes[i].n); }
static int is_dead(int i) { return ((unsigned long)nodes[i].n.n_klist & 1) != 0; }

static sem_t gate_in, gate_out; static struct klist_node *held;
static void *holder(void *a)
{
	struct klist_iter it; struct task_struct me; sem_init(&me.wake, 0, 0); current = &me;
	klist_iter_init_node(&k, &it, held); sem_post(&gate_in);
	usleep(100000); klist_iter_exit(&it); sem_post(&gate_out);
	return NULL;
}

int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("KL_N") ? atol(getenv("KL_N")) : 20000; int prove = getenv("KL_PROVE") != NULL;
	struct task_struct me; sem_init(&me.wake, 0, 0); current = &me;
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (int i = 0; i < NN; i++) nodes[i].id = i;
	klist_init(&k, kget, kput);
	for (long s = 0; s < n; s++) {
		int a = rnd(NN), b = rnd(NN), i = rnd(NI); unsigned op = rnd(100); struct klist_node *r;
		if (op < 25) {
			if (!attached(a)) {
				switch (rnd(4)) {
				case 0: klist_add_head(&nodes[a].n, &k); printf("%ld head %d\n", s, a); break;
				case 1: klist_add_tail(&nodes[a].n, &k); printf("%ld tail %d\n", s, a); break;
				case 2: if (attached(b)) { klist_add_behind(&nodes[a].n, &nodes[b].n); printf("%ld behind %d %d\n", s, a, b); } else printf("%ld skip\n", s); break;
				default: if (attached(b)) { klist_add_before(&nodes[a].n, &nodes[b].n); printf("%ld before %d %d\n", s, a, b); } else printf("%ld skip\n", s); break;
				}
			} else printf("%ld skip\n", s);
		} else if (op < 40) {
			if (attached(a) && !is_dead(a)) { klist_del(&nodes[a].n); printf("%ld del %d\n", s, a); } else printf("%ld skip\n", s);
		} else if (op < 45) {
			if (attached(a) && !is_dead(a) && nodes[a].n.n_ref.refcount.refs == 1) { klist_remove(&nodes[a].n); printf("%ld remove %d\n", s, a); } else printf("%ld skip\n", s);
		} else if (op < 50) {
			printf("%ld attached %d -> %d\n", s, a, attached(a));
		} else if (op < 58) {
			if (!it_live[i]) { if (rnd(2)) klist_iter_init(&k, &its[i]); else klist_iter_init_node(&k, &its[i], attached(a) ? &nodes[a].n : (rnd(2) ? NULL : &nodes[a].n)); it_live[i] = 1; printf("%ld iter_init %d\n", s, i); }
			else printf("%ld skip\n", s);
		} else if (op < 85) {
			if (it_live[i]) { r = rnd(3) ? klist_next(&its[i]) : klist_prev(&its[i]); printf("%ld step %d -> %d\n", s, i, idof(r)); } else printf("%ld skip\n", s);
		} else {
			if (it_live[i]) { klist_iter_exit(&its[i]); it_live[i] = 0; printf("%ld iter_exit %d\n", s, i); } else printf("%ld skip\n", s);
		}
		if (prove && s == 20) printf("  POISON\n");
		state();
	}
	for (int i = 0; i < NI; i++) if (it_live[i]) klist_iter_exit(&its[i]);
	/* threaded phase: a node held by another thread's iterator; klist_remove() must not return before that iterator exits */
	for (int i = 0; i < NN; i++) if (attached(i) && !is_dead(i)) klist_del(&nodes[i].n);
	for (int round = 0; round < 3; round++) {
		pthread_t t; int id = 5; sem_init(&gate_in, 0, 0); sem_init(&gate_out, 0, 0);
		while (attached(id)) id = (id + 1) % NN;
		klist_add_tail(&nodes[id].n, &k); held = &nodes[id].n;
		pthread_create(&t, NULL, holder, NULL); sem_wait(&gate_in);
		klist_remove(&nodes[id].n);
		int after = sem_trywait(&gate_out) == 0;
		printf("round %d: remove returned after the holder exited: %d attached=%d\n", round, after, attached(id));
		pthread_join(t, NULL);
	}
	state();
	printf("final warn=%d\n", warn_count);
	return 0;
}
