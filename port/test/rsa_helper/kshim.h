#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
/* the three things the pristine rsa_get_* functions use besides plain C: struct rsa_key (include/crypto/internal/rsa.h,
 * copied: no Kconfig-dependent member), fips_enabled (an int with CONFIG_CRYPTO_FIPS, the constant 0 without; FIPS=1 in
 * the build of this harness selects the first) and pr_err (printk at KERN_ERR, "\0013", with no pr_fmt prefix here) */
struct rsa_key {
	const u8 *n, *e, *d, *p, *q, *dp, *dq, *qinv;
	size_t n_sz, e_sz, d_sz, p_sz, q_sz, dp_sz, dq_sz, qinv_sz;
};
#ifdef FIPS
extern int fips_enabled;
#else
#define fips_enabled 0
#endif
int _printk(const char *fmt, ...);
#define pr_err(fmt, ...) _printk("\001" "3" fmt, ##__VA_ARGS__)
