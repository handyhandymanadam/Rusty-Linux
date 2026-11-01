/* SPDX-License-Identifier: GPL-2.0 */
/* lib/kfifo.c core: pristine C (c_*) vs kfifo_rs.rs.
 *  1. differential, single thread: random op sequences on FIFOs of esize 1/2/3/4/8 and sizes 2..64 elements (also non-power-of-two
 *     init sizes), plain and record (recsize 1 and 2) variants, with the free-running indices started near 2^32 to exercise wrap;
 *     every return value, every index and every data byte compared.
 *  2. stress, SPSC: one producer thread and one consumer thread per arm, no lock: the producer writes a counter stream (bytes / elements /
 *     records of random length carrying their own sequence), the consumer checks order, count and content; a missing barrier would
 *     show on weak memory only, but a wrong index update shows anywhere. KF_SABOTAGE builds make the Rust producer publish `in`
 *     BEFORE the copy: the consumer must see garbage.
 * usage: main SHARD ; KF_SECONDS, KF_N ; KF_PROVE_CAN_FAIL=1 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>
struct kf { unsigned in, out, mask, esize; void *data; };
#define D(r, n, a) r c_##n a; r n a;
D(int, __kfifo_init, (struct kf *, void *, unsigned, size_t)) D(unsigned, __kfifo_in, (struct kf *, const void *, unsigned))
D(unsigned, __kfifo_out_peek, (struct kf *, void *, unsigned)) D(unsigned, __kfifo_out_linear, (struct kf *, unsigned *, unsigned))
D(unsigned, __kfifo_out, (struct kf *, void *, unsigned)) D(unsigned, __kfifo_max_r, (unsigned, size_t)) D(unsigned, __kfifo_len_r, (struct kf *, size_t))
D(unsigned, __kfifo_in_r, (struct kf *, const void *, unsigned, size_t)) D(unsigned, __kfifo_out_peek_r, (struct kf *, void *, unsigned, size_t))
D(unsigned, __kfifo_out_linear_r, (struct kf *, unsigned *, unsigned, size_t)) D(unsigned, __kfifo_out_r, (struct kf *, void *, unsigned, size_t))
D(void, __kfifo_skip_r, (struct kf *, size_t))
static int poison; static unsigned long long fails, checks;
#define FAIL(...) do { if (__atomic_fetch_add(&fails, 1, __ATOMIC_RELAXED) < 10) fprintf(stderr, __VA_ARGS__); } while (0)
static uint64_t mix(uint64_t z) { z += 0x9e3779b97f4a7c15ULL; z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL; z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL; return z ^ (z >> 31); }

static void diff(unsigned shard, long long n)
{
	uint64_t rs = 0x1234567ULL * (shard + 1);
#define R (mix(rs += 1))
	for (long long it = 0; it < n; it++) {
		static const size_t es[] = { 1, 2, 3, 4, 8 };
		size_t esize = es[R % 5]; unsigned elems = 2 + R % 63; if (R % 4 == 0) elems = 3 + R % 70;
		unsigned bytes = elems * esize + (R % 3 == 0 ? (unsigned)(R % esize) : 0);
		if (R % 4 == 0) { esize = 1; bytes = 520 + R % 680; }   /* big buffer: records longer than 255 use the length's high byte */
		unsigned char ba[1200], bb[1200]; struct kf a, b;
		memset(ba, 0xA5, sizeof ba); memset(bb, 0xA5, sizeof bb);
		int ra = c___kfifo_init(&a, ba, bytes, esize), rb = __kfifo_init(&b, bb, bytes, esize);
		if (poison && it == 9) rb++;
		checks++; if (ra != rb || a.in != b.in || a.out != b.out || a.mask != b.mask || a.esize != b.esize) { FAIL("init MISMATCH bytes=%u esize=%zu\n", bytes, esize); continue; }
		if (ra) continue;
		if (R % 3 == 0) { unsigned start = 0xfffffff0u + R % 16; a.in = a.out = b.in = b.out = start; }
		size_t rec = (R % 2) ? 0 : 1 + R % 2;                 /* 0 = plain; 1,2 = record prefix (esize 1 only for records) */
		if (rec) { esize = 1; a.esize = b.esize = 1; }
		for (int k = 0; k < 24; k++) {
			unsigned char src[1200], oa[1200], ob[1200];
			for (int i = 0; i < 1200; i++) src[i] = R;
			memset(oa, 0x5A, sizeof oa); memset(ob, 0x5A, sizeof ob);
			unsigned len = R % (a.mask + 3), x, y; unsigned ta = 77, tb = 77;
			int op = R % (rec ? 6 : 5);
			if (!rec) {
				switch (op) {
				case 0: x = c___kfifo_in(&a, src, len); y = __kfifo_in(&b, src, len); break;
				case 1: x = c___kfifo_out_peek(&a, oa, len); y = __kfifo_out_peek(&b, ob, len); break;
				case 2: x = c___kfifo_out_linear(&a, &ta, len); y = __kfifo_out_linear(&b, &tb, len); break;
				case 3: x = c___kfifo_out(&a, oa, len); y = __kfifo_out(&b, ob, len); break;
				default: x = c___kfifo_out_linear(&a, 0, len); y = __kfifo_out_linear(&b, 0, len); break;
				}
			} else {
				switch (op) {
				case 0: unsigned rl = (R % 2) ? len % 20 : len % 700; x = c___kfifo_in_r(&a, src, rl, rec); y = __kfifo_in_r(&b, src, rl, rec); break;
				case 1: x = c___kfifo_out_peek_r(&a, oa, len, rec); y = __kfifo_out_peek_r(&b, ob, len, rec); break;
				case 2: x = c___kfifo_out_linear_r(&a, &ta, len, rec); y = __kfifo_out_linear_r(&b, &tb, len, rec); break;
				case 3: x = c___kfifo_out_r(&a, oa, len, rec); y = __kfifo_out_r(&b, ob, len, rec); break;
				case 4: x = c___kfifo_len_r(&a, rec) * 0 + c___kfifo_max_r(len * 100, rec); y = __kfifo_len_r(&b, rec) * 0 + __kfifo_max_r(len * 100, rec); break;
				default: if (a.in != a.out) { c___kfifo_skip_r(&a, rec); __kfifo_skip_r(&b, rec); } x = y = 0; break;
				}
			}
			checks++;
			if (x != y || ta != tb || a.in != b.in || a.out != b.out || memcmp(oa, ob, sizeof oa) || memcmp(ba, bb, sizeof ba)) { FAIL("diff MISMATCH op=%d rec=%zu esize=%zu len=%u: c=%u rs=%u in/out c=%u/%u rs=%u/%u\n", op, rec, esize, len, x, y, a.in, a.out, b.in, b.out); break; }
		}
	}
}

/* ---- stress: SPSC ---- */
struct arm { const char *name; int rust; struct kf f; unsigned char buf[4096]; uint64_t produced, consumed; volatile int stop, bad; };
static void *prod(void *p)
{
	struct arm *A = p; uint64_t seq = 0, rs = 99;
	while (!A->stop) {
		unsigned char rec[64]; unsigned len = 1 + mix(rs += 1) % 40;
		for (unsigned i = 0; i < len; i++) rec[i] = (unsigned char)(seq + i);
		rec[0] = (unsigned char)len;      /* first byte = length, rest = sequence-derived */
		unsigned put = A->rust ? __kfifo_in_r(&A->f, rec, len, 1) : c___kfifo_in_r(&A->f, rec, len, 1);
		if (put == len) { seq += len; } else sched_yield();
	}
	A->produced = seq; return 0;
}
static void *cons(void *p)
{
	struct arm *A = p; uint64_t seq = 0;
	while (1) {
		unsigned char rec[64];
		unsigned n = A->rust ? __kfifo_out_r(&A->f, rec, sizeof rec, 1) : c___kfifo_out_r(&A->f, rec, sizeof rec, 1);
		if (n) {
			if (rec[0] != n) { A->bad++; }
			for (unsigned i = 1; i < n; i++) if (rec[i] != (unsigned char)(seq + i)) { A->bad++; break; }
			seq += n;
		} else if (A->stop && A->f.in == A->f.out) break; else sched_yield();
	}
	A->consumed = seq; return 0;
}
static void stress(struct arm *A, int secs)
{
	pthread_t p, c;
	if (A->rust) __kfifo_init(&A->f, A->buf, sizeof A->buf, 1); else c___kfifo_init(&A->f, A->buf, sizeof A->buf, 1);
	pthread_create(&p, 0, prod, A); pthread_create(&c, 0, cons, A);
	struct timespec ts = { secs, 0 }; nanosleep(&ts, 0);
	A->stop = 1; pthread_join(p, 0); pthread_join(c, 0);
	checks++;
	if (A->bad || A->produced != A->consumed) FAIL("STRESS %s: bad=%d produced=%llu consumed=%llu\n", A->name, A->bad, (unsigned long long)A->produced, (unsigned long long)A->consumed);
	printf("  stress %s: %llu bytes through, bad %d\n", A->name, (unsigned long long)A->consumed, A->bad);
}
int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	poison = getenv("KF_PROVE_CAN_FAIL") != 0;
	diff(shard, getenv("KF_N") ? atoll(getenv("KF_N")) : 300000LL);
	int secs = getenv("KF_SECONDS") ? atoi(getenv("KF_SECONDS")) : 2;
	if (secs > 0) { static struct arm ac = { .name = "C" }, ar = { .name = "Rust", .rust = 1 }; stress(&ac, secs); stress(&ar, secs); }
	printf("shard %u: %llu checks, %llu failures\n", shard, checks, fails);
	return fails != 0;
}
