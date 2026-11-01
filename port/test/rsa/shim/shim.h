/* Stand-ins for the kernel headers crypto/rsa.c includes, just enough to compile the UNMODIFIED pristine file and the glue
 * (rsa_glue.c) as userspace translation units. The mpi_* API is the mock in mpi_mock.c (GMP). Selected with -I port/test/rsa/shim. */
#ifndef RSA_SHIM_H
#define RSA_SHIM_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
typedef uint8_t u8; typedef uint32_t u32;
#define fallthrough __attribute__((fallthrough))
#define unlikely(x) __builtin_expect(!!(x), 0)
#define __init
#define __exit
#define module_init(f)
#define module_exit(f)
#define MODULE_ALIAS_CRYPTO(x)
#define MODULE_LICENSE(x)
#define MODULE_DESCRIPTION(x)
#define THIS_MODULE ((void *)0)
#define BYTES_PER_MPI_LIMB 8
#ifdef FIPS
extern int fips_enabled;
#else
#define fips_enabled 0
#endif
/* include/linux/mpi.h (the parts rsa.c uses) */
struct gcry_mpi { int alloced; int nlimbs; int nbits; int sign; unsigned flags; unsigned long *d; };
typedef struct gcry_mpi *MPI;
struct scatterlist { u8 *buf; size_t len; };
MPI mpi_alloc(unsigned nlimbs);
void mpi_free(MPI a);
MPI mpi_read_raw_data(const void *xbuffer, size_t nbytes);
MPI mpi_read_raw_from_sgl(struct scatterlist *sgl, unsigned int len);
int mpi_write_to_sgl(MPI a, struct scatterlist *sg, unsigned nbytes, int *sign);
int mpi_powm(MPI res, MPI base, MPI exp, MPI mod);
int mpi_cmp_ui(MPI u, unsigned long v);
int mpi_cmp(MPI u, MPI v);
int mpi_sub_ui(MPI w, MPI u, unsigned long vval);
int mpi_test_bit(MPI a, unsigned int n);
int mpi_set_bit(MPI a, unsigned int n);
int mpi_sub(MPI w, MPI u, MPI v);
int mpi_addm(MPI w, MPI u, MPI v, MPI m);
int mpi_mul(MPI w, MPI u, MPI v);
int mpi_mulm(MPI w, MPI u, MPI v, MPI m);
static inline unsigned int mpi_get_size(MPI a) { return a->nlimbs * BYTES_PER_MPI_LIMB; }
/* include/crypto/internal/rsa.h */
struct rsa_key {
	const u8 *n, *e, *d, *p, *q, *dp, *dq, *qinv;
	size_t n_sz, e_sz, d_sz, p_sz, q_sz, dp_sz, dq_sz, qinv_sz;
};
int rsa_parse_pub_key(struct rsa_key *rsa_key, const void *key, unsigned int key_len);
int rsa_parse_priv_key(struct rsa_key *rsa_key, const void *key, unsigned int key_len);
/* include/crypto/akcipher.h, algapi.h (what rsa.c touches) */
struct crypto_alg { const char *cra_name; const char *cra_driver_name; int cra_priority; void *cra_module; unsigned int cra_ctxsize; };
struct crypto_template;
struct crypto_akcipher { unsigned int reqsize; struct { void *ctx; } base; };
struct akcipher_request { struct crypto_akcipher *tfm; struct scatterlist *src, *dst; unsigned int src_len, dst_len; };
struct akcipher_alg {
	int (*encrypt)(struct akcipher_request *req);
	int (*decrypt)(struct akcipher_request *req);
	int (*set_pub_key)(struct crypto_akcipher *tfm, const void *key, unsigned int keylen);
	int (*set_priv_key)(struct crypto_akcipher *tfm, const void *key, unsigned int keylen);
	unsigned int (*max_size)(struct crypto_akcipher *tfm);
	int (*init)(struct crypto_akcipher *tfm);
	void (*exit)(struct crypto_akcipher *tfm);
	struct crypto_alg base;
};
static inline struct crypto_akcipher *crypto_akcipher_reqtfm(struct akcipher_request *req) { return req->tfm; }
static inline void *akcipher_tfm_ctx(struct crypto_akcipher *tfm) { return tfm->base.ctx; }
int crypto_register_akcipher(struct akcipher_alg *alg);
void crypto_unregister_akcipher(struct akcipher_alg *alg);
int crypto_register_template(struct crypto_template *tmpl);
void crypto_unregister_template(struct crypto_template *tmpl);
extern struct crypto_template rsa_pkcs1pad_tmpl, rsassa_pkcs1_tmpl;
#endif
