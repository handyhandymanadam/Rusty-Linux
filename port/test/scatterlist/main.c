/* port/test/scatterlist/main.c -- lib/scatterlist.c: the same program linked once against the pristine C and once against scatterlist_glue.c over
 * scatterlist_rs.rs. Each case builds scatterlist tables / page lists / iterators from a seeded RNG, runs the public API, and folds everything
 * observable (return values, table headers, the structure of the lists, page identities, mapped offsets, copied bytes, page contents, allocation
 * counts and gfp masks, free-callback arguments, warnings) into one hash; the program prints one hash per case and run.sh compares the two outputs
 * line for line. usage: main SHARD ; SG_N cases ; SG_TRACE=<case> prints every folded value of that case to stderr ; SG_PROVE=1 (Rust arm) poisons case 3 */
#include "kshim.h"

int warn_count;
struct page g_pages[NPAGES];
unsigned char g_pagedata[NPAGES][4096];
int g_atomic_depth, g_flushes;

static uint64_t H;
static long trace_case = -1, cur_case;
static void hx(uint64_t v)
{
	if (cur_case == trace_case) fprintf(stderr, "  hx %llu\n", (unsigned long long)v);
	H = (H ^ v) * 1099511628211ULL;
}

/* ---- allocation shim: single-failure injection over every allocation, leak accounting ---- */
static int alloc_n, fail_at = -1;
static void *tracked[16384]; static int ntracked, live_blocks;
static int page_live[NPAGES]; static int live_pages;
static unsigned next_pfn_alloc;
static void *tr_alloc(size_t n)
{
	if (alloc_n++ == fail_at) return NULL;
	void *p = malloc(n ? n : 1);
	memset(p, 0xAA, n);
	tracked[ntracked++] = p; live_blocks++;
	return p;
}
void *kmalloc_array(size_t n, size_t size, gfp_t gfp)
{
	hx(0x1000 + gfp);                              /* the gfp mask the allocator sees */
	if (n * size == 0) return (void *)16;
	return tr_alloc(n * size);
}
void kfree(const void *p)
{
	if (!p || p == (void *)16) return;
	for (int i = 0; i < ntracked; i++) if (tracked[i] == p) { tracked[i] = tracked[--ntracked]; live_blocks--; free((void *)p); return; }
	fprintf(stderr, "BAD FREE %p\n", p); abort();
}
unsigned long __get_free_page(gfp_t gfp) { hx(0x2000 + gfp); return (unsigned long)tr_alloc(4096); }
void free_page(unsigned long addr) { kfree((void *)addr); }
struct page *alloc_pages(gfp_t gfp, unsigned int order)
{
	hx(0x3000 + gfp * 16 + order);
	if (alloc_n++ == fail_at) return NULL;
	unsigned n = 1u << order;
	if (next_pfn_alloc + n > NPAGES) return NULL;
	struct page *p = &g_pages[next_pfn_alloc];
	for (unsigned i = 0; i < n; i++) page_live[next_pfn_alloc + i] = 1;
	live_pages += n; next_pfn_alloc += n;
	return p;
}
void __free_pages(struct page *page, unsigned int order)
{
	hx(0x4000 + page->pfn * 16 + order);
	for (unsigned i = 0; i < (1u << order); i++) {
		if (!page_live[page->pfn + i]) { fprintf(stderr, "BAD PAGE FREE %lu\n", page->pfn + i); abort(); }
		page_live[page->pfn + i] = 0; live_pages--;
	}
}

static uint64_t rs_;
static uint64_t R(void) { rs_ ^= rs_ << 13; rs_ ^= rs_ >> 7; rs_ ^= rs_ << 17; return rs_; }
static unsigned RN(unsigned n) { return n ? R() % n : 0; }

/* the callbacks handed to __sg_alloc_table / __sg_free_table */
static struct scatterlist *test_alloc(unsigned int n, gfp_t gfp) { hx(0x5000 + n); hx(gfp); return tr_alloc(n * sizeof(struct scatterlist)); }
static void test_free(struct scatterlist *sg, unsigned int n) { hx(0x6000 + n); kfree(sg); }

static void hash_list(struct scatterlist *sgl, unsigned limit)
{
	unsigned k = 0;
	for (struct scatterlist *sg = sgl; sg && k < limit; sg = sg_next(sg), k++) {
		hx(sg->page_link & SG_PAGE_LINK_MASK);
		hx(sg->offset); hx(sg->length);
		hx(sg_page(sg) ? sg_page(sg)->pfn + 1 : 0);
#ifndef NODMA
		hx(sg->dma_length); hx(sg->dma_flags); hx(sg->dma_address);
#endif
	}
	hx(0x7000 + k);
}
static void hash_table(const struct sg_table *t) { hx(t->nents); hx(t->orig_nents); hx(t->sgl != NULL); }
static void hash_pages(unsigned n) { for (unsigned i = 0; i < n; i++) { uint64_t v = 0; for (int j = 0; j < 4096; j += 8) v = v * 31 + *(uint64_t *)&g_pagedata[i][j]; hx(v); } }

static void reset_pages(unsigned seed)
{
	for (unsigned i = 0; i < NPAGES; i++) { g_pages[i].pfn = i; g_pages[i].pgmap = 0; }
	for (unsigned i = 0; i < 512; i++) memset(g_pagedata[i], (int)(i * 7 + seed), 4096);
	next_pfn_alloc = 512;
}

/* give every entry a page span: base page, offset (sometimes past one page), length, dma length */
static unsigned fill_entries(struct scatterlist *sgl, unsigned n, unsigned *total)
{
	unsigned k = 0; struct scatterlist *sg; unsigned i; *total = 0;
	for_each_sg(sgl, sg, n, i) {
		unsigned off = RN(4) == 0 ? RN(3 * 4096 + 10) : RN(4096);
		unsigned len = RN(8) == 0 ? 0 : RN(3) == 0 ? RN(4096) : RN(3 * 4096);
		unsigned span = (off + len + 4095) / 4096; if (!span) span = 1;
		struct page *pg = &g_pages[RN(500 - span)];
		sg_set_page(sg, pg, len, off);
#ifndef NODMA
		sg->dma_length = RN(3) == 0 ? len : RN(3 * 4096); sg->dma_address = R();
#endif
		*total += len; k++;
	}
	return k;
}

static void case_tables(void)
{
	unsigned nents = 1 + RN(RN(5) == 0 ? 500 : 40), max_ents = RN(3) == 0 ? SG_MAX_SINGLE_ALLOC : 2 + RN(12);
	unsigned nfc = RN(3) == 0 ? 2 + RN(8) : 0;
	static struct scatterlist fc[16];
	memset(fc, 0xAA, sizeof fc);
	struct sg_table t; memset(&t, 0xAB, sizeof t);
	int use_default = RN(4) == 0;
	int ret;
	if (use_default) ret = sg_alloc_table(&t, nents, GFP_KERNEL | RN(2));
	else {
		ret = __sg_alloc_table(&t, nents, max_ents, nfc ? fc : NULL, nfc, GFP_KERNEL | RN(2), test_alloc);
		if (ret) __sg_free_table(&t, max_ents, nfc, test_free, t.orig_nents);
	}
	hx(ret + 1000); hash_table(&t);
	if (ret) return;
	unsigned total, k = fill_entries(t.sgl, t.orig_nents, &total);
	hx(k); hx(total);
	hash_list(t.sgl, 100000);
	hx(sg_nents(t.sgl));
	for (int j = 0; j < 4; j++) { uint64_t len = RN(4) == 0 ? 0 : RN(total + 100); hx(sg_nents_for_len(t.sgl, len)); }
	hx(sg_nents_for_len(t.sgl, (1ULL << 40) + RN(10)));
	{   /* lengths landing exactly on, one under and one over a running sum */
		uint64_t run = 0; struct scatterlist *e; unsigned q;
		for_each_sg(t.sgl, e, t.orig_nents, q) { run += e->length; if (RN(3) == 0) { hx(sg_nents_for_len(t.sgl, run)); hx(sg_nents_for_len(t.sgl, run + 1)); hx(sg_nents_for_len(t.sgl, run ? run - 1 : 0)); } }
	}
	struct scatterlist *last = sg_last(t.sgl, sg_nents(t.sgl));
	hx(sg_is_last(last)); hx(last->length);
	/* a mid-list start: sg_last needs only the count of entries from there */
	struct scatterlist *mid = t.sgl; unsigned steps = RN(sg_nents(t.sgl)); for (unsigned j = 0; j < steps; j++) mid = sg_next(mid);
	hx(sg_last(mid, sg_nents(mid)) == last);
	/* sg_init_table on a scratch array */
	static struct scatterlist scratch[40]; memset(scratch, 0xCD, sizeof scratch);
	unsigned sn = 1 + RN(39); sg_init_table(scratch, sn); hash_list(scratch, 100);
	hx(sg_nents(scratch));
	if (use_default) sg_free_table(&t); else __sg_free_table(&t, max_ents, nfc, test_free, t.orig_nents);
	hx(t.sgl == NULL);
}

static void case_iters(void)
{
	struct sg_table t;
	unsigned nents = 1 + RN(RN(5) == 0 ? 200 : 12);
	if (sg_alloc_table(&t, nents, GFP_KERNEL)) { hx(0xdead); return; }
	unsigned total, k = fill_entries(t.sgl, t.orig_nents, &total);
	hx(k); hx(total);
	unsigned nargs[3] = { t.orig_nents, RN(t.orig_nents + 2), t.orig_nents + RN(3) };
	/* page iterator, CPU and DMA flavours */
	for (int f = 0; f < 3; f++) {
		struct sg_page_iter pi; struct sg_dma_page_iter di;
		unsigned n = nargs[f], pgoff = RN(3) ? 0 : RN(6);
		if (f == 2) { __sg_page_iter_start(&di.base, t.sgl, n, pgoff); for (int j = 0; j < 2000 && __sg_page_iter_dma_next(&di); j++) { hx(di.base.sg_pgoffset); hx(di.base.__nents); hx(di.base.sg ? di.base.sg->length : 7); } hx(0xd0); continue; }
		__sg_page_iter_start(&pi, t.sgl, n, pgoff);
		for (int j = 0; j < 2000 && __sg_page_iter_next(&pi); j++) { hx(pi.sg_pgoffset); hx(pi.__nents); hx(sg_page_iter_page(&pi)->pfn); }
		hx(0xa0 + pi.__nents); hx(pi.sg_pgoffset);
	}
	/* mapping iterator: random sequences of skip / next / stop with partial consumption and writes */
	static const unsigned flagset[] = { SG_MITER_LOCAL | SG_MITER_TO_SG, SG_MITER_LOCAL | SG_MITER_FROM_SG, SG_MITER_ATOMIC | SG_MITER_TO_SG,
		SG_MITER_ATOMIC | SG_MITER_FROM_SG, SG_MITER_TO_SG, SG_MITER_FROM_SG, 0, SG_MITER_LOCAL };
	for (int m = 0; m < 3; m++) {
		struct sg_mapping_iter mi; memset(&mi, 0xEE, sizeof mi);
		unsigned fl = flagset[RN(8)];
		sg_miter_start(&mi, t.sgl, nargs[RN(3)], fl);
		hx(mi.__flags); hx(mi.length); hx(mi.piter.__nents);
		for (int s = 0, nsteps = 1 + RN(14); s < nsteps; s++) {
			unsigned op = RN(6);
			if (op == 0) { off_t o = (off_t)RN(total + 50); bool r = sg_miter_skip(&mi, o); hx(r); hx(mi.__offset); hx(mi.__remaining); hx(mi.piter.sg_pgoffset); hx(mi.addr == NULL); }
			else if (op == 1) { sg_miter_stop(&mi); hx(mi.addr == NULL); hx(mi.__offset); hx(mi.__remaining); }
			else {
				bool r = sg_miter_next(&mi);
				hx(r);
				if (r) {
					hx(mi.page->pfn); hx((unsigned char *)mi.addr - &g_pagedata[0][0]); hx(mi.length); hx(mi.consumed);
					hx(mi.__offset); hx(mi.__remaining); hx(g_atomic_depth);
					if ((fl & SG_MITER_TO_SG) && RN(2)) for (size_t b = 0; b < mi.length && b < 16; b++) ((unsigned char *)mi.addr)[b] ^= 0x5A;
					if (RN(3) == 0) mi.consumed = RN(mi.length + 1);
					if (RN(40) == 0) { mi.consumed = mi.length + 1; sg_miter_stop(&mi); hx(0xbad); mi.addr = NULL; break; }   /* the WARN_ON in sg_miter_stop; the iterator is abandoned (its state is garbage after) */
				}
			}
		}
		sg_miter_stop(&mi);
		hx(g_atomic_depth); hx(g_flushes);
		g_atomic_depth = 0;
	}
	hash_pages(512);
	/* copy / zero */
	static unsigned char buf[40000];
	for (int c = 0; c < 6; c++) {
		for (unsigned b = 0; b < sizeof buf; b++) buf[b] = (unsigned char)(b * 13 + c);
		size_t buflen = RN(4) == 0 ? sizeof buf : RN(total + 100); if (buflen > sizeof buf) buflen = sizeof buf;
		off_t skip = RN(2) ? 0 : (off_t)RN(total + 50);
		unsigned n = nargs[RN(3)];
		size_t r;
		switch (c) {
		case 0: r = sg_copy_from_buffer(t.sgl, n, buf, buflen); break;
		case 1: r = sg_copy_to_buffer(t.sgl, n, buf, buflen); break;
		case 2: r = sg_pcopy_from_buffer(t.sgl, n, buf, buflen, skip); break;
		case 3: r = sg_pcopy_to_buffer(t.sgl, n, buf, buflen, skip); break;
		case 4: r = sg_zero_buffer(t.sgl, n, buflen, skip); break;
		default: r = sg_copy_buffer(t.sgl, n, buf, buflen, skip, RN(2)); break;
		}
		hx(r); uint64_t v = 0; for (size_t b = 0; b < sizeof buf; b++) v = v * 131 + buf[b]; hx(v);
		hx(g_atomic_depth); hx(g_flushes);
	}
	hash_pages(512);
	sg_free_table(&t);
}

/* entries whose offset + length wraps 32 bits: only the page iterators (which just count pages) may look at them */
static void case_wild(void)
{
	struct sg_table t;
	if (sg_alloc_table(&t, 1 + RN(6), GFP_KERNEL)) { hx(0xdead); return; }
	unsigned total, k = fill_entries(t.sgl, t.orig_nents, &total); (void)k;
	struct scatterlist *sg; unsigned i;
	for_each_sg(t.sgl, sg, t.orig_nents, i) {
		unsigned v = RN(3);
		if (v == 0) { sg->offset = RN(4096); sg->length = (unsigned)(-(int)RN(9000)); }
		else if (v == 1) { sg->offset = RN(3) ? 0xFFFFF000u + RN(0x1000) : RN(4096); sg->length = RN(8192); }
		else { sg->offset = RN(4096); sg->length = 0xFFFFFFFFu - RN(2 * 4096); }
#ifndef NODMA
		sg->dma_length = RN(2) ? (unsigned)(-(int)RN(9000)) : RN(5000);
#endif
	}
	for (int f = 0; f < 2; f++) {
		struct sg_page_iter pi; struct sg_dma_page_iter di;
		if (f) { __sg_page_iter_start(&di.base, t.sgl, t.orig_nents, RN(3)); for (int j = 0; j < 40 && __sg_page_iter_dma_next(&di); j++) { hx(di.base.sg_pgoffset); hx(di.base.__nents); } hx(di.base.__nents); }
		else { __sg_page_iter_start(&pi, t.sgl, t.orig_nents, RN(3)); for (int j = 0; j < 40 && __sg_page_iter_next(&pi); j++) { hx(pi.sg_pgoffset); hx(pi.__nents); } hx(pi.__nents); }
	}
	sg_free_table(&t);
}

static unsigned build_pages(struct page **pages, unsigned n, unsigned startpfn)
{
	unsigned pfn = startpfn, run = 0;
	for (unsigned i = 0; i < n; i++) {
		if (run == 0) { pfn = RN(3) ? pfn + 1 + RN(20) : RN(5) ? pfn : RN(600); if (pfn > 800) pfn = RN(300); run = 1 + RN(RN(4) == 0 ? 20 : 4); }
		else pfn++;
		run--;
		pages[i] = &g_pages[pfn];
		g_pages[pfn].pgmap = RN(30) == 0;
	}
	return pfn;
}

static void case_pages(void)
{
	static const unsigned segs[] = { 4096, 8192, 16384, 65536, 5000, 100, 0, UINT_MAX, 4096 * 3, 4096 * 7 + 1, 0xFFFFF000u, 7000, 6200 };
	static struct page *pages[512];
	if (RN(2)) {   /* the one-shot wrapper */
		struct sg_table t; memset(&t, 0xAB, sizeof t);
		unsigned n = 1 + RN(RN(6) == 0 ? 400 : 40), off = RN(4096); build_pages(pages, n, RN(400));
		unsigned long size = RN(6) == 0 ? RN(n * 4096UL) : (n * 4096UL > off ? n * 4096UL - off : 1);
		unsigned ms = segs[RN(13)];
		int r = sg_alloc_table_from_pages_segment(&t, pages, n, off, size, ms, GFP_KERNEL | RN(2));
		hx(r + 2000);
		if (!r) { hash_table(&t); hash_list(t.sgl, 10000); hx(sg_nents(t.sgl)); sg_free_table(&t); }
		return;
	}
	struct sg_append_table ap; memset(&ap, 0, sizeof ap);
	unsigned ncalls = 1 + RN(3), nextpfn = RN(300), ns[3], left_after[3];
	int failed = 0;
	/* left_pages is the number of pages the caller still has to add after this call: an honest count (an underestimate makes
	 * get_next_sg() chain a short chunk that __sg_free_table() cannot walk -- an upstream limit, not something to compare) */
	for (unsigned c = 0; c < ncalls; c++) ns[c] = 1 + RN(RN(6) == 0 ? 300 : 30);
	for (unsigned c = 0; c < ncalls; c++) { left_after[c] = 0; for (unsigned d = c + 1; d < ncalls; d++) left_after[c] += ns[d]; }
	for (unsigned c = 0; c < ncalls && !failed; c++) {
		unsigned n = ns[c], off = c == 0 ? RN(4096) : (RN(8) == 0 ? 1 : 0);
		/* later calls often continue where the previous one stopped, so the merge-into-previous-entry path runs */
		unsigned start = (c > 0 && RN(3)) ? nextpfn : RN(400);
		nextpfn = build_pages(pages, n, start);
		if (c > 0 && RN(3)) { for (unsigned i = 0; i < n; i++) pages[i] = &g_pages[start + i]; nextpfn = start + n - 1; }
		unsigned long size = RN(6) == 0 ? RN(n * 4096UL + 1) : (n * 4096UL > off ? n * 4096UL - off : 1);
		unsigned ms = segs[RN(13)];
		int r = sg_alloc_append_table_from_pages(&ap, pages, n, off, size, ms, left_after[c], GFP_KERNEL | RN(2));
		hx(r + 3000); hash_table(&ap.sgt); hx(ap.total_nents); hx(ap.prv != NULL);
		if (ap.sgt.sgl) { hash_list(ap.sgt.sgl, 10000); hx(sg_nents(ap.sgt.sgl)); }
		if (r) failed = 1;
	}
	sg_free_append_table(&ap);
}

/* two honest append calls whose second one first merges into the previous entry and then needs a second chunk: with the chunk allocation
 * failing, the merged length must be put back */
static void case_pages_big(void)
{
	static struct page *pages[512];
	struct sg_append_table ap; memset(&ap, 0, sizeof ap);
	unsigned n0 = 60 + RN(60), n1 = 60 + RN(60), base = RN(100), off0 = RN(4096);
	for (unsigned i = 0; i < n0; i++) { pages[i] = &g_pages[base + 2 * i]; pages[i]->pgmap = 0; }
	fail_at = RN(3) ? 1 : (int)RN(3);
	int r = sg_alloc_append_table_from_pages(&ap, pages, n0, off0, n0 * 4096UL - off0, UINT_MAX, n1, GFP_KERNEL);
	hx(r + 4000); hash_table(&ap.sgt); hx(ap.total_nents);
	if (!r) {
		unsigned last = base + 2 * (n0 - 1);
		pages[0] = &g_pages[last + 1];
		for (unsigned i = 1; i < n1; i++) pages[i] = &g_pages[last + 1 + 2 * i];
		for (unsigned i = 0; i < n1; i++) pages[i]->pgmap = 0;
		r = sg_alloc_append_table_from_pages(&ap, pages, n1, 0, n1 * 4096UL, UINT_MAX, 0, GFP_KERNEL);
		hx(r + 5000); hash_table(&ap.sgt); hx(ap.total_nents); hx(ap.prv != NULL);
	}
	if (ap.sgt.sgl) { hash_list(ap.sgt.sgl, 10000); hx(sg_nents(ap.sgt.sgl)); }
	sg_free_append_table(&ap);
}

/* the merge-into-previous-entry limit: the previous entry plus one page lands exactly on max_segment */
static void case_pages_edge(void)
{
	static struct page *pages[16];
	struct sg_append_table ap; memset(&ap, 0, sizeof ap);
	unsigned k = 1 + RN(4), base = 10 + RN(100), extra = 1 + RN(3);
	unsigned ms = (k + 1) * 4096 + (RN(3) == 0 ? RN(4096) : 0);
	for (unsigned i = 0; i < k; i++) pages[i] = &g_pages[base + i];
	int r = sg_alloc_append_table_from_pages(&ap, pages, k, 0, k * 4096UL, ms, extra, GFP_KERNEL);
	hx(r + 6000);
	for (unsigned i = 0; i < extra; i++) pages[i] = &g_pages[base + k + i];
	if (!r) r = sg_alloc_append_table_from_pages(&ap, pages, extra, 0, extra * 4096UL, ms, 0, GFP_KERNEL);
	hx(r + 7000); hash_table(&ap.sgt); hx(ap.total_nents);
	if (ap.sgt.sgl) { hash_list(ap.sgt.sgl, 100); hx(sg_nents(ap.sgt.sgl)); }
	sg_free_append_table(&ap);
}

static void case_sgl(void)
{
	unsigned order = RN(4) == 0 ? RN(4) : 0, nent = 0xCAFE;
	unsigned long long len;
	switch (RN(8)) {
	case 0: len = (1ULL << 44) + RN(100); break;              /* nent wraps to 0 */
	case 1: len = ((unsigned long long)UINT_MAX << (12 + order)) - RN(3); break;
	case 2: len = 1 + RN(10); break;
	case 3: len = (unsigned long long)(1 + RN(20)) << (12 + order); break;     /* exact multiples of the block size */
	default: len = 1 + RN(RN(4) == 0 ? 400000 : 30000); break;
	}
	bool chain = RN(2);
	gfp_t gfp = GFP_KERNEL | (RN(3) == 0 ? GFP_DMA : 0);
	struct scatterlist *sgl;
	if (RN(3)) sgl = sgl_alloc_order(len, order, chain, gfp, &nent);
	else { order = 0; sgl = sgl_alloc(len, gfp, RN(2) ? &nent : NULL); }
	hx(sgl != NULL); hx(nent);
	if (!sgl) return;
	hash_list(sgl, 1000);
	hx(sg_nents(sgl));
	unsigned how = RN(3);
	if (how == 0) sgl_free(sgl);
	else if (how == 1) sgl_free_order(sgl, order);
	else sgl_free_n_order(sgl, (int)(nent ? RN(nent + 1) : 0), order);
	hx(live_pages);
	/* sgl_free_n_order with fewer entries leaves pages live: release them so the leak check below stays meaningful */
	for (unsigned i = 512; i < NPAGES; i++) if (page_live[i]) { page_live[i] = 0; live_pages--; }
}

int main(int argc, char **argv)
{
	unsigned shard = argc > 1 ? atoi(argv[1]) : 0;
	long n = getenv("SG_N") ? atol(getenv("SG_N")) : 3000;
	if (getenv("SG_TRACE")) trace_case = atol(getenv("SG_TRACE"));
#ifdef ARM_RS
	int prove = getenv("SG_PROVE") != 0;
#else
	int prove = 0;
#endif
	setvbuf(stdout, NULL, _IOLBF, 0);
	rs_ = 0x9e3779b97f4a7c15ULL * (shard + 1);
	for (long i = 0; i < n; i++) {
		cur_case = i;
		H = 14695981039346656037ULL;
		reset_pages(i);
		unsigned kind = RN(5);
		alloc_n = 0; fail_at = RN(4) == 0 ? (int)RN(6) : -1;   /* set before the kind is drawn, so it is drawn first */
		int w0 = warn_count;
		if (kind == 0) case_tables(); else if (kind == 1) case_iters(); else if (kind == 2) { { unsigned v = RN(8); if (v == 0) case_pages_big(); else if (v == 1) case_pages_edge(); else case_pages(); } } else if (kind == 3) case_sgl(); else case_wild();
		int fail_save = fail_at; fail_at = -1;
		hx(alloc_n); hx(warn_count - w0); hx(live_blocks); hx(live_pages);
		if (prove && i == 3) hx(12345);
		printf("%ld %016llx\n", i, (unsigned long long)H);
		if (live_blocks) { fprintf(stderr, "LEAK %d blocks after case %ld (kind %u, fail_at %d, allocs %d)\n", live_blocks, i, kind, fail_save, alloc_n); }
		ntracked = 0; live_blocks = 0; live_pages = 0; memset(page_live, 0, sizeof page_live);
	}
	return 0;
}
