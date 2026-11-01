/* Userspace stand-ins for the kernel headers lib/nlattr.c needs: the same struct layouts and the same inline helpers, copied from
 * include/uapi/linux/netlink.h, include/linux/netlink.h and include/net/netlink.h (6.18.49). The real layouts are asserted against the
 * kernel headers at kernel build time by static_asserts in nlattr_glue.c. */
#ifndef KSHIM_H
#define KSHIM_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;
typedef uint16_t __be16; typedef uint32_t __be32; typedef unsigned gfp_t;
#define U8_MAX 255
#define U16_MAX 65535
#define U32_MAX 0xffffffffU
#define U64_MAX (~0ULL)
#define S8_MAX 127
#define S8_MIN (-128)
#define S16_MAX 32767
#define S16_MIN (-32768)
#define S32_MAX 0x7fffffff
#define S32_MIN (-S32_MAX - 1)
#define S64_MAX 0x7fffffffffffffffLL
#define S64_MIN (-S64_MAX - 1)
#define BIT(n) (1U << (n))
#define EXPORT_SYMBOL(x)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x) __builtin_expect(!!(x), 1)
#define fallthrough __attribute__((__fallthrough__))
#define min_t(t, a, b) ((t)(a) < (t)(b) ? (t)(a) : (t)(b))
#define GFP_KERNEL 0
#define kmalloc(n, f) malloc(n)

/* events the harness compares between the arms */
extern int ev_warn, ev_bug;
void ev_log(const char *fmt, ...);
void do_trace_netlink_extack(const char *msg);
struct task_comm { char comm[16]; };
extern struct task_comm *current;
#define WARN_ON_ONCE(c) ({ int _c = !!(c); if (_c) ev_warn++; _c; })
#define WARN_ON(c) ({ int _c = !!(c); if (_c) ev_warn++; _c; })
#define BUG_ON(c) do { if (c) { ev_bug++; fprintf(stderr, "BUG_ON fired\n"); abort(); } } while (0)
#define pr_warn_ratelimited(fmt, ...) ev_log("pr: " fmt, ##__VA_ARGS__)

static inline unsigned long array_index_mask_nospec(unsigned long index, unsigned long size)
{
	unsigned long mask;
	__asm__ volatile ("cmp %1,%2; sbb %0,%0;" : "=r" (mask) : "g"(size), "r" (index) : "cc");
	return mask;
}
#define array_index_nospec(index, size) ({ __typeof__(index) _i = (index); __typeof__(size) _s = (size); \
	unsigned long _mask = array_index_mask_nospec(_i, _s); (__typeof__(_i)) (_i & _mask); })

#define NLA_ALIGNTO 4
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))
#define NLA_F_NESTED (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
struct nlattr { u16 nla_len; u16 nla_type; };
struct nla_bitfield32 { u32 value; u32 selector; };
enum { NLA_UNSPEC, NLA_U8, NLA_U16, NLA_U32, NLA_U64, NLA_STRING, NLA_FLAG, NLA_MSECS, NLA_NESTED, NLA_NESTED_ARRAY, NLA_NUL_STRING,
       NLA_BINARY, NLA_S8, NLA_S16, NLA_S32, NLA_S64, NLA_BITFIELD32, NLA_REJECT, NLA_BE16, NLA_BE32, NLA_SINT, NLA_UINT, __NLA_TYPE_MAX };
#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)
enum nla_policy_validation { NLA_VALIDATE_NONE, NLA_VALIDATE_RANGE, NLA_VALIDATE_RANGE_WARN_TOO_LONG, NLA_VALIDATE_MIN, NLA_VALIDATE_MAX,
			     NLA_VALIDATE_MASK, NLA_VALIDATE_RANGE_PTR, NLA_VALIDATE_FUNCTION };
enum netlink_validation { NL_VALIDATE_LIBERAL = 0, NL_VALIDATE_TRAILING = BIT(0), NL_VALIDATE_MAXTYPE = BIT(1), NL_VALIDATE_UNSPEC = BIT(2),
			  NL_VALIDATE_STRICT_ATTRS = BIT(3), NL_VALIDATE_NESTED = BIT(4) };
#define NL_VALIDATE_STRICT (NL_VALIDATE_TRAILING | NL_VALIDATE_MAXTYPE | NL_VALIDATE_UNSPEC | NL_VALIDATE_STRICT_ATTRS | NL_VALIDATE_NESTED)
struct netlink_ext_ack;
struct netlink_range_validation { u64 min, max; };
struct netlink_range_validation_signed { s64 min, max; };
struct nla_policy {
	u8 type; u8 validation_type; u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		const struct netlink_range_validation *range;
		const struct netlink_range_validation_signed *range_signed;
		struct { s16 min, max; };
		int (*validate)(const struct nlattr *attr, struct netlink_ext_ack *extack);
	};
};
#define NETLINK_MAX_COOKIE_LEN 20
#define NETLINK_MAX_FMTMSG_LEN 80
struct netlink_ext_ack {
	const char *_msg; const struct nlattr *bad_attr; const struct nla_policy *policy; const struct nlattr *miss_nest; u16 miss_type;
	u8 cookie[NETLINK_MAX_COOKIE_LEN]; u8 cookie_len; char _msg_buf[NETLINK_MAX_FMTMSG_LEN];
};
#define NL_SET_ERR_MSG(extack, msg) do { static const char __msg[] = msg; struct netlink_ext_ack *__extack = (extack); \
	do_trace_netlink_extack(__msg); if (__extack) __extack->_msg = __msg; } while (0)
#define NL_SET_BAD_ATTR_POLICY(extack, attr, pol) do { if ((extack)) { (extack)->bad_attr = (attr); (extack)->policy = (pol); } } while (0)
#define NL_SET_BAD_ATTR(extack, attr) NL_SET_BAD_ATTR_POLICY(extack, attr, NULL)
#define NL_SET_ERR_MSG_ATTR_POL(extack, attr, pol, msg) do { static const char __msg[] = msg; struct netlink_ext_ack *__extack = (extack); \
	do_trace_netlink_extack(__msg); if (__extack) { __extack->_msg = __msg; __extack->bad_attr = (attr); __extack->policy = (pol); } } while (0)
#define NL_SET_ERR_MSG_ATTR(extack, attr, msg) NL_SET_ERR_MSG_ATTR_POL(extack, attr, NULL, msg)

static inline int nla_attr_size(int payload) { return NLA_HDRLEN + payload; }
static inline int nla_total_size(int payload) { return NLA_ALIGN(nla_attr_size(payload)); }
static inline int nla_len(const struct nlattr *nla) { return nla->nla_len - NLA_HDRLEN; }
static inline int nla_type(const struct nlattr *nla) { return nla->nla_type & NLA_TYPE_MASK; }
static inline void *nla_data(const struct nlattr *nla) { return (char *) nla + NLA_HDRLEN; }
static inline int nla_ok(const struct nlattr *nla, int remaining)
{ return remaining >= (int) sizeof(*nla) && nla->nla_len >= sizeof(*nla) && nla->nla_len <= remaining; }
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{ unsigned int totlen = NLA_ALIGN(nla->nla_len); *remaining -= totlen; return (struct nlattr *) ((char *) nla + totlen); }
#define nla_for_each_attr(pos, head, len, rem) for (pos = head, rem = len; nla_ok(pos, rem); pos = nla_next(pos, &(rem)))
int nla_memcpy(void *dest, const struct nlattr *src, int count);
static inline u32 nla_get_u32(const struct nlattr *nla) { return *(u32 *) nla_data(nla); }
static inline __be32 nla_get_be32(const struct nlattr *nla) { return *(__be32 *) nla_data(nla); }
static inline u16 nla_get_u16(const struct nlattr *nla) { return *(u16 *) nla_data(nla); }
static inline __be16 nla_get_be16(const struct nlattr *nla) { return *(__be16 *) nla_data(nla); }
static inline u8 nla_get_u8(const struct nlattr *nla) { return *(u8 *) nla_data(nla); }
static inline u64 nla_get_u64(const struct nlattr *nla) { u64 tmp; nla_memcpy(&tmp, nla, sizeof(tmp)); return tmp; }
static inline u64 nla_get_uint(const struct nlattr *nla) { if (nla_len(nla) == sizeof(u32)) return nla_get_u32(nla); return nla_get_u64(nla); }
static inline s32 nla_get_s32(const struct nlattr *nla) { return *(s32 *) nla_data(nla); }
static inline s16 nla_get_s16(const struct nlattr *nla) { return *(s16 *) nla_data(nla); }
static inline s8 nla_get_s8(const struct nlattr *nla) { return *(s8 *) nla_data(nla); }
static inline s64 nla_get_s64(const struct nlattr *nla) { s64 tmp; nla_memcpy(&tmp, nla, sizeof(tmp)); return tmp; }
static inline s64 nla_get_sint(const struct nlattr *nla) { if (nla_len(nla) == sizeof(s32)) return nla_get_s32(nla); return nla_get_s64(nla); }
#endif
