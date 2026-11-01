#ifndef SHIM_POLICYDB_H
#define SHIM_POLICYDB_H
#include "refshim.h"
struct policydb { unsigned int policyvers; unsigned int ntypes, nclasses; };
struct policy_file { char *data; size_t len; };
#define POLICYDB_VERSION_AVTAB 20
#define POLICYDB_VERSION_XPERMS_IOCTL 30
#define POLICYDB_VERSION_COND_XPERMS 34
static inline int policydb_type_isvalid(struct policydb *p, unsigned int type) { return type != 0 && type <= p->ntypes; }
static inline int policydb_class_isvalid(struct policydb *p, unsigned int c) { return c != 0 && c <= p->nclasses; }
static inline int next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
	if (bytes > fp->len) return -EINVAL;
	memcpy(buf, fp->data, bytes); fp->data += bytes; fp->len -= bytes; return 0;
}
static inline int put_entry(const void *buf, size_t bytes, size_t num, struct policy_file *fp)
{
	size_t len;
	if (unlikely(check_mul_overflow(bytes, num, &len))) return -EINVAL;
	if (len > fp->len) return -EINVAL;
	memcpy(fp->data, buf, len); fp->data += len; fp->len -= len; return 0;
}
#define pr_warn_once_policyload(policy, fmt, ...)    \
	do {                                         \
		static const void *prev_policy__;    \
		if (prev_policy__ != policy) {       \
			pr_warn(fmt, ##__VA_ARGS__); \
			prev_policy__ = policy;      \
		}                                    \
	} while (0)
#endif
