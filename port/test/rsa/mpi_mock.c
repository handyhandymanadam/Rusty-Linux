/* SPDX-License-Identifier: GPL-2.0 */
/* The mpi_* API crypto/rsa.c calls, as a GMP-backed mock with fault injection, an operation trace and a live-object count.
 * Both arms (the pristine C and glue+Rust) link THIS, so a difference between them is a difference in what rsa.c / rsa_rs.rs
 * ask of the MPI layer (which calls, in which order, with which values, and whether they free what they allocated), never in
 * the MPI layer. struct gcry_mpi is the real layout (the C inline mpi_get_size() and the Rust mirror read nlimbs from it). */
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include "shim.h"

struct mock { struct gcry_mpi h; mpz_t z; };
long g_create_seq, g_fail_create_at = -1, g_op_seq, g_fail_op_at = -1, g_live, g_calls;
uint64_t g_trace;
int g_parse_ret;            /* forced rsa_parse_*_key result */
int g_sign_neg;             /* make mpi_write_to_sgl report a negative number */

static void mix(uint64_t v) { g_trace = (g_trace ^ v) * 1099511628211ULL; }
static void mixz(const mpz_t z)
{
	size_t n = mpz_size(z);
	mix(0xabc0 + (mpz_sgn(z) < 0));
	for (size_t i = 0; i < n; i++) mix(mpz_getlimbn(z, i));
}
static void sync(struct mock *m)
{
	m->h.nlimbs = (int)mpz_size(m->z);
	m->h.sign = mpz_sgn(m->z) < 0;
	m->h.nbits = (int)mpz_sizeinbase(m->z, 2);
	m->h.alloced = m->h.nlimbs;
}
static struct mock *newm(void)
{
	struct mock *m = calloc(1, sizeof *m);
	mpz_init(m->z); g_live++;
	return m;
}
#define Z(a) (((struct mock *)(a))->z)
mpz_ptr mock_z(MPI a) { return Z(a); }
void mock_set(MPI a, const mpz_t v) { mpz_set(Z(a), v); sync((struct mock *)a); }
/* a creation point: the nth (counting alloc and both raw readers) fails when armed */
static int create_fails(int id) { mix(id); g_calls++; if (g_create_seq++ == g_fail_create_at) { mix(0xdead); return 1; } return 0; }
static int op_fails(int id) { mix(id); g_calls++; if (g_op_seq++ == g_fail_op_at) { mix(0xbeef); return 1; } return 0; }

MPI mpi_alloc(unsigned nlimbs) { (void)nlimbs; if (create_fails(1)) return NULL; return (MPI)newm(); }
void mpi_free(MPI a) { mix(2); if (!a) return; mpz_clear(Z(a)); free(a); g_live--; }
MPI mpi_read_raw_data(const void *buf, size_t nbytes)
{
	struct mock *m;
	if (create_fails(3)) return NULL;
	m = newm(); mix(nbytes);
	if (nbytes) mpz_import(m->z, nbytes, 1, 1, 0, 0, buf);
	sync(m); mixz(m->z); return (MPI)m;
}
MPI mpi_read_raw_from_sgl(struct scatterlist *sgl, unsigned int len)
{
	struct mock *m;
	if (create_fails(4)) return NULL;
	m = newm(); mix(len);
	if (len) mpz_import(m->z, len, 1, 1, 0, 0, sgl->buf);
	sync(m); mixz(m->z); return (MPI)m;
}
int mpi_write_to_sgl(MPI a, struct scatterlist *sg, unsigned nbytes, int *sign)
{
	size_t need = mpz_size(Z(a)) * 8, cnt = 0;    /* the real mpi_write_to_sgl compares nbytes with mpi_get_size(a) = nlimbs * 8 */
	if (op_fails(5)) return -ENOMEM;
	mixz(Z(a)); mix(nbytes);
	*sign = (g_sign_neg || mpz_sgn(Z(a)) < 0) ? -1 : 0;
	if (nbytes < need) return -EOVERFLOW;
	memset(sg->buf, 0, nbytes);
	if (mpz_sgn(Z(a))) { size_t nb = (mpz_sizeinbase(Z(a), 2) + 7) / 8; mpz_export(sg->buf + (nbytes - nb), &cnt, 1, 1, 0, 0, Z(a)); }
	return 0;
}
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod)
{
	if (op_fails(6)) return -ENOMEM;
	mixz(Z(base)); mixz(Z(exp)); mixz(Z(mod));
	if (!mpz_sgn(Z(mod)) || mpz_sgn(Z(exp)) < 0) return -EINVAL;
	mpz_powm(Z(res), Z(base), Z(exp), Z(mod)); sync((struct mock *)res); mixz(Z(res)); return 0;
}
int mpi_cmp_ui(MPI u, unsigned long v) { int c = mpz_cmp_ui(Z(u), v); mix(7); mix(v); mixz(Z(u)); g_calls++; return c < 0 ? -1 : c > 0; }
int mpi_cmp(MPI u, MPI v) { int c = mpz_cmp(Z(u), Z(v)); mix(8); mixz(Z(u)); mixz(Z(v)); g_calls++; return c < 0 ? -1 : c > 0; }
int mpi_sub_ui(MPI w, MPI u, unsigned long vv)
{
	if (op_fails(9)) return -ENOMEM;
	mixz(Z(u)); mix(vv); mpz_sub_ui(Z(w), Z(u), vv); sync((struct mock *)w); mixz(Z(w)); return 0;
}
int mpi_sub(MPI w, MPI u, MPI v)
{
	if (op_fails(10)) return -ENOMEM;
	mixz(Z(u)); mixz(Z(v)); mpz_sub(Z(w), Z(u), Z(v)); sync((struct mock *)w); mixz(Z(w)); return 0;
}
int mpi_mul(MPI w, MPI u, MPI v)
{
	if (op_fails(11)) return -ENOMEM;
	mixz(Z(u)); mixz(Z(v)); mpz_mul(Z(w), Z(u), Z(v)); sync((struct mock *)w); mixz(Z(w)); return 0;
}
int mpi_mulm(MPI w, MPI u, MPI v, MPI m)
{
	if (op_fails(12)) return -ENOMEM;
	mixz(Z(u)); mixz(Z(v)); mixz(Z(m));
	if (!mpz_sgn(Z(m))) return -EINVAL;
	mpz_mul(Z(w), Z(u), Z(v)); mpz_mod(Z(w), Z(w), Z(m)); sync((struct mock *)w); mixz(Z(w)); return 0;
}
int mpi_addm(MPI w, MPI u, MPI v, MPI m)
{
	if (op_fails(13)) return -ENOMEM;
	mixz(Z(u)); mixz(Z(v)); mixz(Z(m));
	if (!mpz_sgn(Z(m))) return -EINVAL;
	mpz_add(Z(w), Z(u), Z(v)); mpz_mod(Z(w), Z(w), Z(m)); sync((struct mock *)w); mixz(Z(w)); return 0;
}
int mpi_test_bit(MPI a, unsigned int n) { mix(14); mix(n); g_calls++; return mpz_tstbit(Z(a), n); }
int mpi_set_bit(MPI a, unsigned int n)
{
	if (op_fails(15)) return -ENOMEM;
	mix(n); mpz_setbit(Z(a), n); sync((struct mock *)a); return 0;
}

/* BER parsing is the other file's job: the "key" is a struct parse_in the harness builds */
struct parse_in { struct rsa_key k; };
int rsa_parse_pub_key(struct rsa_key *rk, const void *key, unsigned int len)
{
	mix(16); mix(len);
	if (g_parse_ret) return g_parse_ret;
	*rk = ((const struct parse_in *)key)->k;
	rk->d = rk->p = rk->q = rk->dp = rk->dq = rk->qinv = NULL; rk->d_sz = rk->p_sz = rk->q_sz = rk->dp_sz = rk->dq_sz = rk->qinv_sz = 0;
	return 0;
}
int rsa_parse_priv_key(struct rsa_key *rk, const void *key, unsigned int len)
{
	mix(17); mix(len);
	if (g_parse_ret) return g_parse_ret;
	*rk = ((const struct parse_in *)key)->k;
	return 0;
}
struct crypto_template { int x; } rsa_pkcs1pad_tmpl, rsassa_pkcs1_tmpl;
int crypto_register_akcipher(struct akcipher_alg *a) { (void)a; return 0; }
void crypto_unregister_akcipher(struct akcipher_alg *a) { (void)a; }
int crypto_register_template(struct crypto_template *t) { (void)t; return 0; }
void crypto_unregister_template(struct crypto_template *t) { (void)t; }
#ifdef FIPS
int fips_enabled;
#endif
