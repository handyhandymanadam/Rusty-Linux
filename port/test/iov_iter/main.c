/* port/test/iov_iter/main.c -- differential driver for the ported part of lib/iov_iter.c: the same program is linked against the original
 * functions (extracted from the pristine file) and against iov_iter_rs.rs; each prints one digest per case (every return value and the full
 * iterator state after every operation) and the two outputs must be identical.   t <shard>   env IOV_N cases per shard (default 20000),
 * IOV_PROVE=1 (Rust build only) poisons one result. */
#include "kshim.h"

int warn_count, bug_count;
jmp_buf bug_jmp;

static u64 rs_state = 88172645463325252ULL;
static u64 rnd64(void) { rs_state ^= rs_state << 13; rs_state ^= rs_state >> 7; rs_state ^= rs_state << 17; return rs_state; }
static u32 rn(u32 n) { return n ? (u32)(rnd64() >> 20) % n : 0; }
static u64 dig;
static void mix(u64 v) { for (int k = 0; k < 8; k++) { dig ^= (v >> (k * 8)) & 0xff; dig *= 0x100000001b3ULL; } }

#ifdef ARM_RS
/* the glue's side: thunks and wrappers */
#include <setjmp.h>
void rust_iov_iter_advance(struct iov_iter *, size_t); void rust_iov_iter_revert(struct iov_iter *, size_t);
size_t rust_iov_iter_single_seg_count(const struct iov_iter *); unsigned long rust_iov_iter_alignment(const struct iov_iter *);
unsigned long rust_iov_iter_gap_alignment(const struct iov_iter *); int rust_iov_iter_npages(const struct iov_iter *, int);
void rust_iov_iter_restore(struct iov_iter *, struct iov_iter_state *);
void iov_iter_advance(struct iov_iter *i, size_t s) { rust_iov_iter_advance(i, s); }
void iov_iter_revert(struct iov_iter *i, size_t u) { rust_iov_iter_revert(i, u); }
size_t iov_iter_single_seg_count(const struct iov_iter *i) { return rust_iov_iter_single_seg_count(i); }
unsigned long iov_iter_alignment(const struct iov_iter *i) { return rust_iov_iter_alignment(i); }
unsigned long iov_iter_gap_alignment(const struct iov_iter *i) { return rust_iov_iter_gap_alignment(i); }
int iov_iter_npages(const struct iov_iter *i, int m) { return rust_iov_iter_npages(i, m); }
void iov_iter_restore(struct iov_iter *i, struct iov_iter_state *s) { rust_iov_iter_restore(i, s); }
const size_t rust_iw_folioq_next_off = offsetof(struct folio_queue, next), rust_iw_folioq_prev_off = offsetof(struct folio_queue, prev),
	rust_iw_max_rw_count = MAX_RW_COUNT;
unsigned int rust_iw_folioq_nr_slots(const struct folio_queue *q) { return folioq_nr_slots(q); }
size_t rust_iw_folioq_folio_size(const struct folio_queue *q, unsigned int slot) { return folioq_folio_size(q, slot); }
bool rust_iw_warn_revert(bool c) { return WARN_ON(c); }
void rust_iw_bug_revert(void) { BUG(); }
bool rust_iw_warn_gap(bool c) { return WARN_ON(c); }
bool rust_iw_warn_restore(bool c) { return WARN_ON(c); }
static int prove_poison;
#endif

#define NSEG 8
static struct iovec iov[NSEG + 2];
static struct bio_vec bv[NSEG + 2];
static struct folio_queue fq[3];
static int fq_len;

static size_t folioq_remaining(unsigned slot)   /* bytes from (first segment, slot) to the end of the chain */
{
	size_t t = 0;
	for (int c = 0; c < fq_len; c++)
		for (unsigned k = (c == 0 ? slot : 0); k < PAGEVEC_SIZE; k++) t += folioq_folio_size(&fq[c], k);
	return t;
}

static void make_iter(struct iov_iter *it)
{
	memset(it, 0, sizeof(*it));
	unsigned kind = rn(7), n = 1 + rn(NSEG);
	size_t total = 0;
	switch (kind) {
	case 0:
		it->iter_type = ITER_UBUF; it->ubuf = (void *)(rnd64() & 0xffffffffff); it->count = rn(4) ? rn(1 << 20) : rn(5000);
		it->__ubuf_iovec.iov_len = it->count;   /* the C overlays count with iov_len */
		break;
	case 1: case 2:
		it->iter_type = kind == 1 ? ITER_IOVEC : ITER_KVEC;
		for (unsigned k = 0; k < NSEG + 2; k++) { iov[k].iov_base = (void *)(rnd64() & 0xffffffffff); iov[k].iov_len = rn(5) ? rn(20000) : 0; }
		for (unsigned k = 0; k < n; k++) total += iov[k].iov_len;
		it->__iov = iov; it->nr_segs = n; it->count = rn(3) ? total : (total ? rn(total + 1) : 0);
		if (rn(4) == 0) { size_t pre = 0; for (unsigned k = 0, e = rn(n + 1); k < e; k++) pre += iov[k].iov_len; it->count = pre; }   /* count ends exactly on a segment boundary */
		if (rn(3) == 0 && iov[0].iov_len > 1 && it->count == total) { it->iov_offset = rn(iov[0].iov_len); it->count -= it->iov_offset; }
		break;
	case 3:
		it->iter_type = ITER_BVEC;
		for (unsigned k = 0; k < NSEG + 2; k++) { bv[k].bv_page = NULL; bv[k].bv_len = rn(5) ? rn(20000) : 0; bv[k].bv_offset = rn(8192); }
		for (unsigned k = 0; k < n; k++) total += bv[k].bv_len;
		it->bvec = bv; it->nr_segs = n; it->count = rn(3) ? total : (total ? rn(total + 1) : 0);
		if (rn(4) == 0) { size_t pre = 0; for (unsigned k = 0, e = rn(n + 1); k < e; k++) pre += bv[k].bv_len; it->count = pre; }
		if (rn(3) == 0 && bv[0].bv_len > 1 && it->count == total) { it->iov_offset = rn(bv[0].bv_len); it->count -= it->iov_offset; }
		break;
	case 4: {
		fq_len = 1 + rn(3);
		memset(fq, 0, sizeof(fq));
		for (int c = 0; c < fq_len; c++) {
			for (unsigned k = 0; k < PAGEVEC_SIZE; k++) fq[c].orders[k] = rn(4) ? 0 : rn(4);
			fq[c].next = c + 1 < fq_len ? &fq[c + 1] : NULL; fq[c].prev = c ? &fq[c - 1] : NULL;
		}
		unsigned slot = rn(3) ? 0 : rn(PAGEVEC_SIZE);
		if (fq_len > 1 && rn(6) == 0) slot = PAGEVEC_SIZE;   /* positioned just past the end of the first segment */
		size_t off = (rn(2) || slot == PAGEVEC_SIZE) ? 0 : rn((unsigned)folioq_folio_size(&fq[0], slot));
		size_t rem = folioq_remaining(slot) - off;
		it->iter_type = ITER_FOLIOQ; it->folioq = fq; it->folioq_slot = slot; it->iov_offset = off;
		it->count = rn(3) ? (size_t)rn((unsigned)(rem < 400000 ? rem : 400000) + 1) : rem;
		break; }
	case 5:
		it->iter_type = ITER_XARRAY; it->xarray = (void *)8; it->xarray_start = (loff_t)(rnd64() & 0xffffffffff); it->count = rn(1 << 20);
		break;
	default:
		it->iter_type = ITER_DISCARD; it->count = rn(1 << 20);
	}
}

static void hash_state(const struct iov_iter *it)
{
	mix(it->iter_type); mix(it->iov_offset); mix(it->count);
	switch (it->iter_type) {
	case ITER_UBUF: mix((u64)(uintptr_t)it->ubuf); break;
	case ITER_IOVEC: case ITER_KVEC: mix(it->__iov - iov); mix(it->nr_segs); break;
	case ITER_BVEC: mix(it->bvec - bv); mix(it->nr_segs); break;
	case ITER_FOLIOQ: mix(it->folioq - fq); mix(it->nr_segs); break;
	case ITER_XARRAY: mix((u64)it->xarray_start); break;
	}
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? (unsigned)atoi(argv[1]) : 0;
	unsigned ncase = getenv("IOV_N") ? (unsigned)atoi(getenv("IOV_N")) : 20000;
	for (unsigned n = 0; n < ncase; n++) {
		rs_state = 0x9e3779b97f4a7c15ULL * (shard * 1000003u + n + 1); for (int k = 0; k < 8; k++) rnd64();
		dig = 0xcbf29ce484222325ULL; warn_count = bug_count = 0;
		struct iov_iter it; struct iov_iter_state st; bool saved = false;
		make_iter(&it);
		size_t advanced = 0;
		unsigned nops = 1 + rn(24);
		for (unsigned o = 0; o < nops; o++) {
			unsigned op = rn(10);
			if (op < 3) {
				size_t sz = rn(4) == 0 ? (size_t)rn(100000) : rn(2) ? it.count ? rn((unsigned)it.count + 1) : 0 : rn(8) == 0 ? (size_t)-1 : (size_t)rn(6000);
				size_t before = it.count;
				iov_iter_advance(&it, sz);
				advanced += before - it.count;
			} else if (op < 5) {
				size_t u;
				unsigned m = rn(20);
				if (m == 0) u = (it.iter_type == ITER_DISCARD ? MAX_RW_COUNT : MAX_RW_COUNT + 1) + rn(10);                          /* the WARN path */
				else if (m == 1 && (it.iter_type == ITER_UBUF || it.iter_type == ITER_XARRAY)) u = it.iov_offset + 1 + rn(100);   /* the BUG path */
				else u = advanced ? rn((unsigned)(advanced < 2000000000 ? advanced : 2000000000) + 1) : 0;
				if (u > advanced && !(m == 0 || (m == 1 && (it.iter_type == ITER_UBUF || it.iter_type == ITER_XARRAY)))) u = advanced;
				if (u && u <= MAX_RW_COUNT && u <= advanced) advanced -= u;
				if (setjmp(bug_jmp) == 0) iov_iter_revert(&it, u); else { mix(0xb06); advanced = 0; }
			} else if (op == 5) {
				mix(iov_iter_single_seg_count(&it));
			} else if (op == 6) {
				mix(iov_iter_alignment(&it));
			} else if (op == 7) {
				mix(iov_iter_gap_alignment(&it));
			} else if (op == 8) {
				int r = iov_iter_npages(&it, (int)rn(40)); mix((u64)r);
#ifdef ARM_RS
				if (getenv("IOV_PROVE") && !prove_poison++) mix(7);
#endif
			} else {
				if (!saved || rn(2)) { st.iov_offset = it.iov_offset; st.count = it.count; st.nr_segs = it.nr_segs; saved = true; mix(0x5a); }
				else { iov_iter_restore(&it, &st); advanced = 0; mix(0x5b); }
			}
			hash_state(&it);
		}
		mix(warn_count); mix(bug_count);
		printf("%u.%u %016llx\n", shard, n, (unsigned long long)dig);
	}
	return 0;
}
