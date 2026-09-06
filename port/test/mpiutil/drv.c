/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpiutil/drv.c -- differential for lib/crypto/mpi/mpiutil.c ->
 * mpiutil_rs.rs.
 *
 * Exported: mpi_alloc, mpi_free. Not exported, but real symbols other
 * still-C files in lib/crypto/mpi/ call directly: mpi_alloc_limb_space,
 * mpi_free_limb_space, mpi_assign_limb_space, mpi_resize, mpi_copy.
 *
 * rust_mpi_kmalloc/kcalloc/kfree/kfree_sensitive below stand in for the
 * retained C thunk's real kmalloc()/kcalloc()/kfree()/kfree_sensitive()
 * wrappers (mpiutil.c in port/tree/) -- plain malloc()/calloc()/free() give
 * an identical observable result for everything this differential checks
 * (struct field values and buffer contents), which is what the C arm's own
 * shim/linux/slab.h does for the pristine C side too.
 *
 * The comparison is over STRUCT FIELD VALUES and BUFFER CONTENTS, never
 * raw pointer identity -- the two arms allocate through entirely separate
 * malloc() call sites and will never return the same addresses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

/* _printk(): the Rust arm's mpi_free() calls this directly (see
 * mpiutil_rs.rs), matching the kernel's own real symbol. Userspace has no
 * such thing; a passthrough to vprintf gives an equivalent (if not
 * bit-identical) message, which is all the invalid-flags path in
 * run_free_variants() needs -- that path is checked for "does not crash",
 * not for exact text. */
int _printk(const char *fmt, ...)
{
	va_list ap;
	int ret;
	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return ret;
}

typedef unsigned long mpi_limb_t;
struct gcry_mpi {
	int alloced;
	int nlimbs;
	int nbits;
	int sign;
	unsigned flags;
	mpi_limb_t *d;
};
typedef struct gcry_mpi *MPI;

/* rust_mpi_* -- linked into BOTH arms: the Rust side calls these directly
 * (extern "C"), and they stand in for the retained thunk's real kmalloc
 * wrappers described above. */
void *rust_mpi_kmalloc(size_t len) { return malloc(len); }
void *rust_mpi_kcalloc(size_t n, size_t size) { return calloc(n, size); }
void rust_mpi_kfree(void *p) { free(p); }
void rust_mpi_kfree_sensitive(void *p) { free(p); }

/* ---- C arm (renamed via -D, see run.sh) ---- */
MPI c_mpi_alloc(unsigned nlimbs);
void c_mpi_free(MPI a);
mpi_limb_t *c_mpi_alloc_limb_space(unsigned nlimbs);
void c_mpi_free_limb_space(mpi_limb_t *a);
void c_mpi_assign_limb_space(MPI a, mpi_limb_t *ap, unsigned nlimbs);
int c_mpi_resize(MPI a, unsigned nlimbs);
MPI c_mpi_copy(MPI a);

/* ---- Rust arm (kept at the real names) ---- */
MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
mpi_limb_t *mpi_alloc_limb_space(unsigned nlimbs);
void mpi_free_limb_space(mpi_limb_t *a);
void mpi_assign_limb_space(MPI a, mpi_limb_t *ap, unsigned nlimbs);
int mpi_resize(MPI a, unsigned nlimbs);
MPI mpi_copy(MPI a);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static int mpi_fields_eq(MPI a, MPI b)
{
	return a->alloced == b->alloced && a->nlimbs == b->nlimbs
	    && a->nbits == b->nbits && a->sign == b->sign
	    && a->flags == b->flags;
}

static uint32_t rnd_state = 1;
static unsigned long rnd(void)
{
	rnd_state = rnd_state * 1103515245u + 12345u;
	return rnd_state;
}

/* mpi_alloc() at a spread of sizes, including 0 (no limb buffer). */
static void run_alloc(unsigned nlimbs)
{
	MPI c = c_mpi_alloc(nlimbs);
	MPI r = mpi_alloc(nlimbs);

	cases++;
	if (!c || !r) {
		if (c != NULL || r != NULL)
			bad("mpi_alloc: one arm returned NULL, the other did not");
		return;
	}
	if (!mpi_fields_eq(c, r))
		bad("mpi_alloc: fields differ");
	if (nlimbs == 0) {
		if (c->d != NULL || r->d != NULL)
			bad("mpi_alloc(0): d should be NULL on both arms");
	} else {
		if (!c->d || !r->d)
			bad("mpi_alloc: d is NULL for nonzero nlimbs");
	}

	c_mpi_free(c);
	mpi_free(r);
}

/* mpi_resize(): grow from a small starting size to a larger one, with
 * real data in the old buffer, and confirm it survived the grow -- the
 * thing a copy/free-order bug breaks. Also checks the "already big
 * enough" no-op path. */
static void run_resize(unsigned start, unsigned grow)
{
	MPI c = c_mpi_alloc(start);
	MPI r = mpi_alloc(start);
	unsigned i;
	int rcc, rcr;

	cases++;
	if (!c || !r) { bad("mpi_resize setup: alloc failed"); return; }

	for (i = 0; i < start; i++) {
		c->d[i] = 0x1000 + i;
		r->d[i] = 0x1000 + i;
	}
	c->nlimbs = start;
	r->nlimbs = start;

	rcc = c_mpi_resize(c, grow);
	rcr = mpi_resize(r, grow);
	cases++;
	if (rcc != rcr)
		bad("mpi_resize: return code differs");
	if (!mpi_fields_eq(c, r))
		bad("mpi_resize: fields differ");

	cases++;
	{
		unsigned check_n = start < grow ? start : grow;
		int ok = 1;
		for (i = 0; i < check_n; i++)
			if (c->d[i] != r->d[i] || c->d[i] != (mpi_limb_t)(0x1000 + i))
				ok = 0;
		if (!ok)
			bad("mpi_resize: old data not preserved identically");
	}

	/* Growing again to something smaller than alloced must be a no-op
	 * on both arms (RESIZE_IF_NEEDED's whole premise). */
	{
		unsigned before_c = c->alloced, before_r = r->alloced;
		c_mpi_resize(c, 1);
		mpi_resize(r, 1);
		cases++;
		if (c->alloced != before_c || r->alloced != before_r)
			bad("mpi_resize: shrink request changed alloced");
	}

	c_mpi_free(c);
	mpi_free(r);
}

/* mpi_copy(): the flags-masking (16|32 cleared) and the deep copy of the
 * limb data, not just the pointer. */
static void run_copy(unsigned nlimbs, unsigned extra_flags)
{
	MPI c = c_mpi_alloc(nlimbs);
	MPI r = mpi_alloc(nlimbs);
	unsigned i;
	MPI cc, rr;

	cases++;
	if (!c || !r) { bad("mpi_copy setup: alloc failed"); return; }

	for (i = 0; i < nlimbs; i++) {
		c->d[i] = rnd();
		r->d[i] = c->d[i];
	}
	c->nlimbs = nlimbs;
	r->nlimbs = nlimbs;
	c->sign = nlimbs & 1;
	r->sign = nlimbs & 1;
	c->flags = extra_flags;
	r->flags = extra_flags;

	cc = c_mpi_copy(c);
	rr = mpi_copy(r);
	cases++;
	if (!cc || !rr) { bad("mpi_copy: alloc failed inside copy"); }
	else {
		if (!mpi_fields_eq(cc, rr))
			bad("mpi_copy: fields differ");
		if ((cc->flags & (16u | 32u)) != 0 || (rr->flags & (16u | 32u)) != 0)
			bad("mpi_copy: immutable/constant flag bits not cleared");
		for (i = 0; i < nlimbs; i++)
			if (cc->d[i] != c->d[i] || rr->d[i] != r->d[i] || cc->d[i] != rr->d[i])
				bad("mpi_copy: limb data not copied identically");
		/* A genuine deep copy: mutating the source must not affect
		 * the copy. */
		if (nlimbs > 0) {
			mpi_limb_t save_c = c->d[0], save_r = r->d[0];
			c->d[0] ^= 0xff;
			r->d[0] ^= 0xff;
			cases++;
			if (cc->d[0] != save_c || rr->d[0] != save_r)
				bad("mpi_copy: aliases the source buffer");
			c->d[0] = save_c;
			r->d[0] = save_r;
		}
		c_mpi_free(cc);
		mpi_free(rr);
	}

	c_mpi_free(c);
	mpi_free(r);
}

/* mpi_free(): the flags&4 branch (kfree_sensitive on d directly) versus
 * the default branch (through mpi_free_limb_space). Neither branch is
 * observable from outside except "did not crash", which is what a
 * differential over allocator-backed code can check. */
static void run_free_variants(void)
{
	MPI c, r;

	c = c_mpi_alloc(4);
	r = mpi_alloc(4);
	cases++;
	if (!c || !r) { bad("free-variant setup: alloc failed"); return; }
	c->flags = 4;
	r->flags = 4;
	c_mpi_free(c);
	mpi_free(r);
	printf("(mpi_free flags=4 path: no crash on either arm)\n");

	c = c_mpi_alloc(4);
	r = mpi_alloc(4);
	cases++;
	if (!c || !r) { bad("free-variant setup: alloc failed"); return; }
	c->flags = 0x100; /* outside bits 0-2: the pr_info() warning path */
	r->flags = 0x100;
	c_mpi_free(c);
	mpi_free(r);
	printf("(mpi_free invalid-flags path: no crash on either arm)\n");
}

/* mpi_assign_limb_space(): replaces d and updates alloced; the old buffer
 * must be freed (checked here only by not crashing under a sanitizer-free
 * userspace build -- ASAN would catch a double free or leak, which this
 * harness does not link, so this is a shape check, not a leak check). */
static void run_assign(void)
{
	MPI c = c_mpi_alloc(4);
	MPI r = mpi_alloc(4);
	mpi_limb_t *newc, *newr;

	cases++;
	if (!c || !r) { bad("assign setup: alloc failed"); return; }

	newc = c_mpi_alloc_limb_space(8);
	newr = mpi_alloc_limb_space(8);
	cases++;
	if (!newc || !newr) { bad("assign: mpi_alloc_limb_space failed"); return; }

	c_mpi_assign_limb_space(c, newc, 8);
	mpi_assign_limb_space(r, newr, 8);
	cases++;
	if (c->alloced != r->alloced || c->alloced != 8)
		bad("mpi_assign_limb_space: alloced not updated identically");
	if (c->d != newc || r->d != newr)
		bad("mpi_assign_limb_space: d not replaced");

	c_mpi_free(c);
	mpi_free(r);
}

int main(void)
{
	unsigned n;

	if (getenv("MPIUTIL_PROVE_CAN_FAIL"))
		poison = 1;

	{
		unsigned sizes[] = { 0, 1, 2, 3, 4, 8, 16, 32, 64, 100 };
		for (n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++)
			run_alloc(sizes[n]);
	}

	{
		unsigned starts[] = { 0, 1, 2, 4, 8 };
		unsigned grows[]  = { 1, 2, 4, 8, 16, 32 };
		unsigned si, gi;
		for (si = 0; si < sizeof(starts) / sizeof(starts[0]); si++)
			for (gi = 0; gi < sizeof(grows) / sizeof(grows[0]); gi++)
				if (grows[gi] > starts[si])
					run_resize(starts[si], grows[gi]);
	}

	for (n = 0; n < 200; n++)
		run_copy(rnd() % 32, rnd() & 0x3f);

	run_free_variants();
	run_assign();

	if (poison) {
		/* Prove the harness can disagree: allocate on both arms,
		 * then deliberately corrupt the RUST side's recorded field
		 * before running it through the ordinary comparison. */
		MPI c = c_mpi_alloc(4);
		MPI r = mpi_alloc(4);
		cases++;
		if (!c || !r) {
			bad("poison setup: alloc failed");
		} else {
			r->nlimbs = c->nlimbs + 1;
			if (!mpi_fields_eq(c, r))
				bad("mpi_alloc: fields differ (expected -- poisoned run)");
			c_mpi_free(c);
			mpi_free(r);
		}
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
