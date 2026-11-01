#ifndef SHIM_POLICYDB_H
#define SHIM_POLICYDB_H
#include "refshim.h"
extern long resched_count;
#ifndef cond_resched
#define cond_resched() do { resched_count++; } while (0)
#endif
#include "security.h"
#include "symtab.h"
#include "avtab.h"
#define SYM_COMMONS 0
#define SYM_CLASSES 1
#define SYM_ROLES   2
#define SYM_TYPES   3
#define SYM_USERS   4
#define SYM_BOOLS   5
#define SYM_LEVELS  6
#define SYM_CATS    7
#define SYM_NUM     8
struct cond_bool_datum { u32 value; int state; };
struct cond_node;
struct policydb {
	unsigned int policyvers;     /* real layout differs; the offsets below are the ones conditional_rs.rs reads */
	char pad0[4];
	struct symtab symtab[SYM_NUM];
	char **sym_val_to_name[SYM_NUM];
	char pad1[32];
	struct avtab te_avtab;
	char pad2[56];
	struct cond_bool_datum **bool_val_to_struct;
	struct avtab te_cond_avtab;
	struct cond_node *cond_list;
	u32 cond_list_len;
	char pad3[188];
};
#define p_classes symtab[SYM_CLASSES]
#define p_types   symtab[SYM_TYPES]
#define p_bools   symtab[SYM_BOOLS]
_Static_assert(offsetof(struct policydb, p_bools.table) == 128 && offsetof(struct policydb, p_bools.nprim) == 144 && offsetof(struct policydb, sym_val_to_name[SYM_BOOLS]) == 240 &&
	       offsetof(struct policydb, te_avtab) == 296 && offsetof(struct policydb, bool_val_to_struct) == 376 && offsetof(struct policydb, te_cond_avtab) == 384 &&
	       offsetof(struct policydb, cond_list) == 408 && offsetof(struct policydb, cond_list_len) == 416 && sizeof(struct policydb) == 608, "policydb shim layout");
struct policy_file { char *data; size_t len; };
struct policy_data { struct policydb *p; struct policy_file *fp; };
#define POLICYDB_VERSION_AVTAB 20
#define POLICYDB_VERSION_XPERMS_IOCTL 30
#define POLICYDB_VERSION_COND_XPERMS 34
static inline int policydb_type_isvalid(struct policydb *p, unsigned int type) { return !(!type || type > p->p_types.nprim); }
static inline int policydb_class_isvalid(struct policydb *p, unsigned int c) { return !(!c || c > p->p_classes.nprim); }
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
static inline bool val_is_boolean(u32 value) { return value == 0 || value == 1; }

int str_read(char **strp, int flags, struct policy_file *fp, u32 len);
#endif
