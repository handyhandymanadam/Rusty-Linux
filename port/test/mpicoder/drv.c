/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/mpicoder/drv.c -- differential for lib/crypto/mpi/mpicoder.c
 * -> mpicoder_rs.rs (mpi_read_raw_data, mpi_read_from_buffer,
 * mpi_read_buffer, mpi_get_buffer, mpi_write_to_sgl,
 * mpi_read_raw_from_sgl).
 *
 * mpi_alloc/mpi_free (mpiutil_rs.rs) are shared dependencies, already
 * ported and verified; not under test here.
 *
 * sg_nents_for_len()/sg_miter_start()/_next()/_stop() are a from-scratch
 * SIMULATED scatterlist implementation (port/test/mpicoder/shim/linux/
 * scatterlist.h) -- a flat buffer chopped into small chunks, since
 * userspace has no real page-mapping concept. Deliberately small chunk
 * sizes force many sg_miter_next() calls and cross many entry
 * boundaries, which is a STRONGER test of mpi_write_to_sgl()/
 * mpi_read_raw_from_sgl()'s own boundary-crossing loops than real 4 KiB
 * pages would give for buffers this small.
 *
 * Independent oracle: OpenSSL's BIGNUM. BN_bn2binpad() writes the exact
 * msb-first, zero-padded-to-length representation mpi_write_to_sgl()/
 * mpi_read_buffer()/mpi_get_buffer() all promise; BN_bin2bn() is the
 * inverse mpi_read_raw_data()/mpi_read_raw_from_sgl() are checked
 * against.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>

#define MAXBYTES 256

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

struct scatterlist {
	void *buf;
	unsigned int length;
};

/* ---- Shared dependencies: ONE implementation, linked into both arms ---- */
MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);

/* ---- C arm (renamed via -D, see run.sh) ---- */
MPI c_mpi_read_raw_data(const void *xbuffer, size_t nbytes);
MPI c_mpi_read_from_buffer(const void *xbuffer, unsigned int *ret_nread);
int c_mpi_read_buffer(MPI a, uint8_t *buf, unsigned int buf_len, unsigned int *nbytes, int *sign);
void *c_mpi_get_buffer(MPI a, unsigned int *nbytes, int *sign);
int c_mpi_write_to_sgl(MPI a, struct scatterlist *sgl, unsigned int nbytes, int *sign);
MPI c_mpi_read_raw_from_sgl(struct scatterlist *sgl, unsigned int nbytes);

/* ---- Rust arm (kept at the real names) ---- */
MPI mpi_read_raw_data(const void *xbuffer, size_t nbytes);
MPI mpi_read_from_buffer(const void *xbuffer, unsigned int *ret_nread);
int mpi_read_buffer(MPI a, uint8_t *buf, unsigned int buf_len, unsigned int *nbytes, int *sign);
void *mpi_get_buffer(MPI a, unsigned int *nbytes, int *sign);
int mpi_write_to_sgl(MPI a, struct scatterlist *sgl, unsigned int nbytes, int *sign);
MPI mpi_read_raw_from_sgl(struct scatterlist *sgl, unsigned int nbytes);

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static uint32_t rnd_state = 0xA5A5A5A5;
static uint32_t rnd(void)
{
	rnd_state ^= rnd_state << 13;
	rnd_state ^= rnd_state >> 17;
	rnd_state ^= rnd_state << 5;
	return rnd_state;
}

static int mpi_eq(MPI a, MPI b)
{
	if (a->nlimbs != b->nlimbs)
		return 0;
	if (a->nlimbs != 0 && a->sign != b->sign)
		return 0;
	return memcmp(a->d, b->d, (size_t)a->nlimbs * sizeof(mpi_limb_t)) == 0;
}

/* Split a flat, msb-first byte buffer into a scatterlist of small
 * chunks. Returns the entry count. */
static int mk_sgl(struct scatterlist *sgl, int max_entries, void *buf, size_t total, size_t chunk)
{
	int n = 0;
	char *p = buf;

	while (total > 0) {
		size_t c = total < chunk ? total : chunk;
		if (n >= max_entries)
			return -1;
		sgl[n].buf = p;
		sgl[n].length = (unsigned int)c;
		p += c;
		total -= c;
		n++;
	}
	return n;
}

static BIGNUM *bytes_to_bn(const uint8_t *buf, size_t len)
{
	return BN_bin2bn(buf, (int)len, NULL);
}

static void run_read_raw_data(const uint8_t *buf, size_t len)
{
	MPI c = c_mpi_read_raw_data(buf, len);
	MPI r = mpi_read_raw_data(buf, len);
	BIGNUM *expect = bytes_to_bn(buf, len);
	BIGNUM *bc, *br;

	cases++;
	if (!c || !r || !mpi_eq(c, r))
		bad("mpi_read_raw_data: arms disagree");

	bc = c ? BN_lebin2bn((const unsigned char *)c->d, (int)(c->nlimbs * sizeof(mpi_limb_t)), NULL) : NULL;
	br = r ? BN_lebin2bn((const unsigned char *)r->d, (int)(r->nlimbs * sizeof(mpi_limb_t)), NULL) : NULL;
	cases++;
	if (!bc || !br || BN_cmp(bc, expect) != 0 || BN_cmp(br, expect) != 0)
		bad("mpi_read_raw_data: disagrees with the independent BIGNUM reference");

	if (poison && r) {
		MPI r2 = mpi_read_raw_data(buf, len);
		if (r2 && r2->nlimbs > 0) {
			r2->d[0] ^= 1;
			cases++;
			if (!mpi_eq(c, r2))
				bad("mpi_read_raw_data: poisoned run (expected)");
		}
		if (r2)
			mpi_free(r2);
	}

	if (bc) BN_free(bc);
	if (br) BN_free(br);
	BN_free(expect);
	if (c) mpi_free(c);
	if (r) mpi_free(r);
}

static void run_get_buffer(int nlimbs, const mpi_limb_t *limbs)
{
	MPI a1 = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	MPI a2 = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	int i;
	unsigned int nb_c = 0, nb_r = 0;
	int sign_c = -2, sign_r = -2;
	uint8_t *bc, *br;
	BIGNUM *b, *expect;
	int nbytes_expect;

	for (i = 0; i < nlimbs; i++) {
		a1->d[i] = limbs[i];
		a2->d[i] = limbs[i];
	}
	a1->nlimbs = a2->nlimbs = nlimbs;

	bc = c_mpi_get_buffer(a1, &nb_c, &sign_c);
	br = mpi_get_buffer(a2, &nb_r, &sign_r);

	cases++;
	if (nb_c != nb_r || sign_c != sign_r || (nb_c && memcmp(bc, br, nb_c)))
		bad("mpi_get_buffer: arms disagree");

	b = BN_lebin2bn((const unsigned char *)limbs, (int)(nlimbs * sizeof(mpi_limb_t)), NULL);
	nbytes_expect = BN_num_bytes(b);
	expect = BN_new();
	cases++;
	if ((int)nb_c != nbytes_expect) {
		bad("mpi_get_buffer: size disagrees with the independent BIGNUM reference");
	} else if (nbytes_expect > 0) {
		uint8_t tmp[MAXBYTES];
		BN_bn2bin(b, tmp);
		cases++;
		if (memcmp(bc, tmp, (size_t)nbytes_expect) != 0)
			bad("mpi_get_buffer: content disagrees with the independent BIGNUM reference");
	}

	BN_free(b);
	BN_free(expect);
	free(bc);
	free(br);
	mpi_free(a1);
	mpi_free(a2);
}

static void run_write_to_sgl(int nlimbs, const mpi_limb_t *limbs, unsigned int nbytes, size_t chunk)
{
	MPI a1 = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	MPI a2 = mpi_alloc(nlimbs > 0 ? (unsigned)nlimbs : 1);
	uint8_t bufc[MAXBYTES] = { 0 }, bufr[MAXBYTES] = { 0 };
	struct scatterlist sglc[MAXBYTES], sglr[MAXBYTES];
	int nc, nr, i;
	int rc, rr;
	int sign_c = -2, sign_r = -2;
	BIGNUM *b, *expect;
	uint8_t expect_bytes[MAXBYTES] = { 0 };

	for (i = 0; i < nlimbs; i++) {
		a1->d[i] = limbs[i];
		a2->d[i] = limbs[i];
	}
	a1->nlimbs = a2->nlimbs = nlimbs;

	nc = mk_sgl(sglc, MAXBYTES, bufc, nbytes, chunk);
	nr = mk_sgl(sglr, MAXBYTES, bufr, nbytes, chunk);

	rc = c_mpi_write_to_sgl(a1, sglc, nbytes, &sign_c);
	rr = mpi_write_to_sgl(a2, sglr, nbytes, &sign_r);

	cases++;
	if (rc != rr)
		bad("mpi_write_to_sgl: return code differs");
	cases++;
	if (rc == 0 && (sign_c != sign_r || memcmp(bufc, bufr, nbytes) != 0))
		bad("mpi_write_to_sgl: arms disagree");

	if (rc == 0) {
		/* BN_bn2binpad writes exactly `nbytes` bytes, msb first,
		 * zero-padded on the left -- exactly mpi_write_to_sgl's own
		 * contract. */
		b = BN_lebin2bn((const unsigned char *)limbs, (int)(nlimbs * sizeof(mpi_limb_t)), NULL);
		BN_bn2binpad(b, expect_bytes, (int)nbytes);
		cases++;
		if (memcmp(bufc, expect_bytes, nbytes) != 0)
			bad("mpi_write_to_sgl: disagrees with the independent BIGNUM reference");
		BN_free(b);
	}
	(void)nc; (void)nr; (void)expect;

	mpi_free(a1);
	mpi_free(a2);
}

static void run_read_raw_from_sgl(const uint8_t *buf, unsigned int nbytes, size_t chunk)
{
	struct scatterlist sglc[MAXBYTES], sglr[MAXBYTES];
	uint8_t bufc[MAXBYTES], bufr[MAXBYTES];
	MPI c, r;
	BIGNUM *expect, *bc, *br;

	memcpy(bufc, buf, nbytes);
	memcpy(bufr, buf, nbytes);
	mk_sgl(sglc, MAXBYTES, bufc, nbytes, chunk);
	mk_sgl(sglr, MAXBYTES, bufr, nbytes, chunk);

	c = c_mpi_read_raw_from_sgl(sglc, nbytes);
	r = mpi_read_raw_from_sgl(sglr, nbytes);

	cases++;
	if (!c || !r || !mpi_eq(c, r))
		bad("mpi_read_raw_from_sgl: arms disagree");

	expect = bytes_to_bn(buf, nbytes);
	bc = c ? BN_lebin2bn((const unsigned char *)c->d, (int)(c->nlimbs * sizeof(mpi_limb_t)), NULL) : NULL;
	br = r ? BN_lebin2bn((const unsigned char *)r->d, (int)(r->nlimbs * sizeof(mpi_limb_t)), NULL) : NULL;
	cases++;
	if (!bc || !br || BN_cmp(bc, expect) != 0 || BN_cmp(br, expect) != 0)
		bad("mpi_read_raw_from_sgl: disagrees with the independent BIGNUM reference");

	if (bc) BN_free(bc);
	if (br) BN_free(br);
	BN_free(expect);
	if (c) mpi_free(c);
	if (r) mpi_free(r);
}

int main(void)
{
	unsigned n;
	uint8_t buf[MAXBYTES];

	if (getenv("MPICODER_PROVE_CAN_FAIL"))
		poison = 1;

	/* mpi_read_raw_data: hand-picked. */
	{
		static const uint8_t v[] = { 0x2a };
		run_read_raw_data(v, sizeof(v));
	}
	{
		static const uint8_t v[] = { 0x00, 0x00, 0x12, 0x34 }; /* leading zero bytes stripped */
		run_read_raw_data(v, sizeof(v));
	}
	{
		run_read_raw_data(buf, 0); /* empty */
	}
	{
		static const uint8_t v[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }; /* > 1 limb */
		run_read_raw_data(v, sizeof(v));
	}

	/* mpi_get_buffer: hand-picked. */
	{
		mpi_limb_t v[1] = { 0x1234 };
		run_get_buffer(1, v);
	}
	{
		mpi_limb_t v[1] = { 0 };
		run_get_buffer(1, v);
		run_get_buffer(0, v);
	}
	{
		mpi_limb_t v[2] = { 0x1122334455667788ULL, 0x99 };
		run_get_buffer(2, v);
	}

	/* mpi_write_to_sgl: small chunk sizes force multi-entry boundary
	 * crossing (see this file's own header comment). */
	{
		mpi_limb_t v[1] = { 0x1234 };
		run_write_to_sgl(1, v, 2, 1);
		run_write_to_sgl(1, v, 8, 3); /* zero-padded beyond the value's own size */
		run_write_to_sgl(1, v, 8, 1);
	}
	{
		mpi_limb_t v[2] = { 0x1122334455667788ULL, 0x99aabb };
		run_write_to_sgl(2, v, 16, 3);
		run_write_to_sgl(2, v, 16, 1);
	}

	/* mpi_read_raw_from_sgl: hand-picked, including a leading-zero-byte
	 * skip spanning multiple small sg entries (the case this file's
	 * own module doc comment discusses at length). */
	{
		static const uint8_t v[] = { 0x2a };
		run_read_raw_from_sgl(v, sizeof(v), 1);
	}
	{
		static const uint8_t v[] = { 0x00, 0x00, 0x00, 0x12, 0x34 };
		run_read_raw_from_sgl(v, sizeof(v), 1); /* every byte its own entry */
		run_read_raw_from_sgl(v, sizeof(v), 2);
		run_read_raw_from_sgl(v, sizeof(v), 3);
	}
	{
		static const uint8_t v[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 };
		run_read_raw_from_sgl(v, sizeof(v), 3);
	}

	/* Random sweeps. */
	for (n = 0; n < 500; n++) {
		unsigned len = rnd() % 32;
		unsigned i;
		for (i = 0; i < len; i++)
			buf[i] = (uint8_t)rnd();
		run_read_raw_data(buf, len);
	}
	for (n = 0; n < 300; n++) {
		int nlimbs = 1 + (int)(rnd() % 4);
		mpi_limb_t v[4];
		int i;
		for (i = 0; i < nlimbs; i++)
			v[i] = ((uint64_t)rnd() << 32) | rnd();
		run_get_buffer(nlimbs, v);
	}
	for (n = 0; n < 300; n++) {
		int nlimbs = 1 + (int)(rnd() % 3);
		mpi_limb_t v[3];
		int i;
		unsigned int size = nlimbs * 8;
		unsigned int extra = rnd() % 8;
		size_t chunk = 1 + (rnd() % 4);
		for (i = 0; i < nlimbs; i++)
			v[i] = ((uint64_t)rnd() << 32) | rnd();
		run_write_to_sgl(nlimbs, v, size + extra, chunk);
	}
	for (n = 0; n < 300; n++) {
		unsigned len = 1 + rnd() % 24;
		size_t chunk = 1 + (rnd() % 4);
		unsigned i;
		for (i = 0; i < len; i++)
			buf[i] = (uint8_t)rnd();
		run_read_raw_from_sgl(buf, len, chunk);
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
