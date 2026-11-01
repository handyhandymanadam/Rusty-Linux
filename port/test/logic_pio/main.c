/* logic_pio differential: pristine lib/logic_pio.c (ARM_REF) against logic_pio_glue.c over logic_pio_rs.rs (ARM_RS). 10 range objects, 8 firmware nodes. Ops: register (MMIO / indirect / invalid
 * flag, NULL ops, zero size, sizes up to far too big, overlapping and adjacent hw ranges, a duplicate fwnode), unregister, find_io_range_by_fwnode, to_hwaddr, trans_hwaddr, trans_cpuaddr (all
 * three include the exact edges of every range). After every op the registered ranges, the log lines and the lock/RCU balance are printed. Shards 0-1 use the plain x86 limits (0xffff / 0xffff),
 * 2-3 the CONFIG_INDIRECT_PIO ones (0xffff / 0xbfff) and a larger I/O space.   usage: t SHARD (env LP_N, LP_PROVE=1) */
#include <ctype.h>
#include <linux/logic_pio.h>
u64 lim_io_space, lim_mmio_upper; long rcu_depth, sync_count, mutex_depth;
void klog(const char *tag, const char *fmt, ...)
{
	char o[400]; int n = 0; va_list ap; va_start(ap, fmt);
	for (const char *p = fmt; *p && n < 380; p++) {
		if (p[0] == '%' && p[1] == 'p' && p[2] == 'a') { n += sprintf(o + n, "0x%llx", (unsigned long long)*va_arg(ap, u64 *)); p += 2; }
		else if (p[0] == '%' && p[1] == 'l' && p[2] == 'x') { n += sprintf(o + n, "%lx", va_arg(ap, unsigned long)); p += 2; }
		else o[n++] = *p;
	}
	o[n] = 0; va_end(ap);
	printf("  LOG %s: %s", tag, o);
}
#include SRC

static unsigned long long rs_;
static unsigned rnd(unsigned n) { rs_ = rs_ * 6364136223846793005ULL + 1442695040888963407ULL; return n ? (unsigned)(rs_ >> 40) % n : 0; }
#define NR 10
#define NF 8
static struct logic_pio_hwaddr R[NR]; static int reg[NR]; static struct fwnode_handle F[NF]; static struct logic_pio_host_ops hops;
static int idx_of(struct logic_pio_hwaddr *r) { for (int i = 0; i < NR; i++) if (r == &R[i]) return i; return r ? 99 : -1; }
static void state(void)
{
	printf("  S locks=%ld/%ld rcu=%ld sync=%ld |", mutex_depth, mutex_depth, rcu_depth, sync_count);
	for (struct list_head *p = io_range_list.next; p != &io_range_list; p = p->next) {
		struct logic_pio_hwaddr *r = (void *)p;
		printf(" %d{f%d fl%lu hw%llx io%llx sz%llx}", idx_of(r), (int)(r->fwnode - F), r->flags, (unsigned long long)r->hw_start, (unsigned long long)r->io_start, (unsigned long long)r->size);
	}
	printf("\n");
}
static u64 interesting(void)
{
	/* an edge of a registered range, or a random value */
	u64 v = rnd(1 << 20);
	if (rnd(3)) { int i = rnd(NR); if (reg[i]) { u64 base = rnd(2) ? R[i].hw_start : R[i].io_start; static const long d[] = { -1, 0, 1 }; v = base + (rnd(2) ? 0 : R[i].size) + d[rnd(3)]; } }
	return v;
}
int main(int argc, char **argv)
{
	int shard = argc > 1 ? atoi(argv[1]) : 0; long n = getenv("LP_N") ? atol(getenv("LP_N")) : 40000; int prove = getenv("LP_PROVE") != NULL;
	setvbuf(stdout, NULL, _IOFBF, 1 << 20);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	if (shard & 2) { lim_io_space = 0xffff; lim_mmio_upper = 0xbfff; } else { lim_io_space = 0xffff; lim_mmio_upper = 0xffff; }
	if (shard == 3) lim_io_space = 0x3ffff;
	for (int i = 0; i < NF; i++) F[i].id = i;
	for (long s = 0; s < n; s++) {
		unsigned op = rnd(100); int a = rnd(NR);
		printf("%ld ", s);
		if (op < 35) {
			if (!reg[a]) {
				struct logic_pio_hwaddr *r = &R[a]; memset(r, 0, sizeof *r);
				r->fwnode = rnd(25) ? &F[rnd(NF)] : NULL;
				static const u64 SZ[] = { 0, 1, 0x10, 0x100, 0x1000, 0x4000, 0x8000, 0xc000, 0x10000, 0x20000, 0x1000000 };
				r->size = SZ[rnd(rnd(3) ? 8 : 11)];
				r->hw_start = rnd(2) ? 0x1000 * rnd(40) : (rnd(2) ? 0xf0000000ULL + 0x100 * rnd(20) : rnd(1 << 24));
				r->flags = rnd(10) < 5 ? LOGIC_PIO_CPU_MMIO : (rnd(10) < 8 ? LOGIC_PIO_INDIRECT : 2 + rnd(2));
				r->ops = rnd(8) ? &hops : NULL; r->hostdata = (void *)(long)a;
				int rc = logic_pio_register_range(rnd(40) ? r : NULL);
				if (rc == 0) reg[a] = 1;
				printf("register %d f%d fl%lu hw%llx sz%llx ops%d -> %d\n", a, r->fwnode ? (int)(r->fwnode - F) : -1, r->flags, (unsigned long long)r->hw_start, (unsigned long long)r->size, r->ops != NULL, rc);
			} else printf("skip\n");
		} else if (op < 50) {
			if (reg[a]) { logic_pio_unregister_range(&R[a]); reg[a] = 0; printf("unregister %d\n", a); } else printf("skip\n");
		} else if (op < 60) {
			struct fwnode_handle *f = rnd(10) ? &F[rnd(NF)] : NULL; printf("find_fwnode %d -> %d\n", f ? (int)(f - F) : -1, idx_of(find_io_range_by_fwnode(f)));
		} else if (op < 75) {
			unsigned long pio = rnd(8) ? (unsigned long)interesting() : lim_mmio_upper + rnd(3) - 1; printf("to_hwaddr %lx -> %llx\n", pio, (unsigned long long)logic_pio_to_hwaddr(pio));
		} else if (op < 88) {
			struct fwnode_handle *f = &F[rnd(NF)]; { int i = rnd(NR); if (reg[i] && rnd(4)) f = (struct fwnode_handle *)R[i].fwnode; } u64 sz = rnd(3) ? rnd(0x200) : interesting(), ad = interesting(); { int i = rnd(NR); if (reg[i] && rnd(2)) { sz = rnd(2) ? R[i].size : R[i].size + rnd(3) - 1; ad = R[i].hw_start + rnd(4); } }
			printf("trans_hwaddr f%d addr %llx size %llx -> %lx\n", (int)(f - F), (unsigned long long)ad, (unsigned long long)sz, logic_pio_trans_hwaddr(f, ad, sz));
		} else {
			u64 ad = interesting(); printf("trans_cpuaddr %llx -> %lx\n", (unsigned long long)ad, logic_pio_trans_cpuaddr(ad));
		}
		if (prove && s == 20) printf("  POISON\n");
		state();
		if (mutex_depth || rcu_depth) { printf("LOCK/RCU LEAK\n"); return 1; }
	}
	return 0;
}
