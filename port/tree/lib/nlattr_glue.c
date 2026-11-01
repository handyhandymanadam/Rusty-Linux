// SPDX-License-Identifier: GPL-2.0
/*
 * NETLINK      Netlink attributes
 *
 * 		Authors:	Thomas Graf <tgraf@suug.ch>
 * 				Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/nospec.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/types.h>
#include <net/netlink.h>

/*
 * RUST PORT (lib/nlattr.c, 6.18.49): the attribute walk, the policy validation and the read-only helpers are in nlattr_rs.rs. This
 * file keeps (1) every exported entry point as a thunk -- the MODVERSIONS fingerprints come from the DWARF of the definition --
 * (2) everything that touches struct sk_buff (the nla_reserve/nla_put family, unchanged below), nla_strdup (kmalloc), and (3) one
 * helper per macro site that plants a bug-table or rate-limit entry (WARN_ON_ONCE, WARN_ON, BUG_ON, pr_warn_ratelimited), so each
 * keeps its own once-flag / rate-limit state. Their warnings now name this file, not nlattr.c. Upstream's file is installed as
 * nlattr_norust.c for CONFIG_RUST=n.
 */

/*
 * The layouts and constants nlattr_rs.rs assumes, checked here against the real headers at every build.
 */
static_assert(sizeof(struct nlattr) == 4);
static_assert(sizeof(struct nla_policy) == 16);
static_assert(offsetof(struct nla_policy, validate) == 8);
static_assert(offsetof(struct nla_policy, nested_policy) == 8);
static_assert(offsetof(struct nla_policy, reject_message) == 8);
static_assert(offsetof(struct nla_policy, range) == 8);
static_assert(offsetof(struct nla_policy, range_signed) == 8);
static_assert(offsetof(struct nla_policy, bitfield32_valid) == 8);
static_assert(offsetof(struct nla_policy, mask) == 8);
static_assert(offsetof(struct nla_policy, strict_start_type) == 8);
static_assert(offsetof(struct nla_policy, min) == 8 && offsetof(struct nla_policy, max) == 10);
static_assert(offsetof(struct netlink_ext_ack, _msg) == 0 && offsetof(struct netlink_ext_ack, bad_attr) == 8 &&
	      offsetof(struct netlink_ext_ack, policy) == 16);
static_assert(sizeof(struct netlink_range_validation) == 16 && sizeof(struct netlink_range_validation_signed) == 16);
static_assert(NLA_UNSPEC == 0 && NLA_U8 == 1 && NLA_U16 == 2 && NLA_U32 == 3 && NLA_U64 == 4 && NLA_STRING == 5 && NLA_FLAG == 6 &&
	      NLA_MSECS == 7 && NLA_NESTED == 8 && NLA_NESTED_ARRAY == 9 && NLA_NUL_STRING == 10 && NLA_BINARY == 11 && NLA_S8 == 12 &&
	      NLA_S16 == 13 && NLA_S32 == 14 && NLA_S64 == 15 && NLA_BITFIELD32 == 16 && NLA_REJECT == 17 && NLA_BE16 == 18 &&
	      NLA_BE32 == 19 && NLA_SINT == 20 && NLA_UINT == 21 && NLA_TYPE_MAX == 21);
static_assert(NLA_VALIDATE_NONE == 0 && NLA_VALIDATE_RANGE == 1 && NLA_VALIDATE_RANGE_WARN_TOO_LONG == 2 && NLA_VALIDATE_MIN == 3 &&
	      NLA_VALIDATE_MAX == 4 && NLA_VALIDATE_MASK == 5 && NLA_VALIDATE_RANGE_PTR == 6 && NLA_VALIDATE_FUNCTION == 7);
static_assert(NL_VALIDATE_TRAILING == 1 && NL_VALIDATE_MAXTYPE == 2 && NL_VALIDATE_UNSPEC == 4 && NL_VALIDATE_STRICT_ATTRS == 8 &&
	      NL_VALIDATE_NESTED == 16);
static_assert(NLA_HDRLEN == 4 && NLA_F_NESTED == 0x8000 && NLA_TYPE_MASK == ~0xc000);

/* lib/nlattr_rs.rs */
int rust_nla_validate(const struct nlattr *head, int len, int maxtype, const struct nla_policy *policy, unsigned int validate,
		      struct netlink_ext_ack *extack);
int rust_nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head, int len, const struct nla_policy *policy,
		   unsigned int validate, struct netlink_ext_ack *extack);
int rust_nla_policy_len(const struct nla_policy *p, int n);
struct nlattr *rust_nla_find(const struct nlattr *head, int len, int attrtype);
ssize_t rust_nla_strscpy(char *dst, const struct nlattr *nla, size_t dstsize);
int rust_nla_memcpy(void *dest, const struct nlattr *src, int count);
int rust_nla_memcmp(const struct nlattr *nla, const void *data, size_t size);
int rust_nla_strcmp(const struct nlattr *nla, const char *str);
void rust_nla_get_range_unsigned(const struct nla_policy *pt, struct netlink_range_validation *range);
void rust_nla_get_range_signed(const struct nla_policy *pt, struct netlink_range_validation_signed *range);

void rust_nla_warn_range_unsigned_neg(bool cond);
void rust_nla_warn_range_unsigned_default(void);
void rust_nla_warn_range_signed_default(void);
void rust_nla_warn_int_range_default(void);
void rust_nla_bug_on_type(bool cond);
void rust_nla_pr_invalid_len(int type);
void rust_nla_pr_invalid_len_range(int type);
void rust_nla_pr_leftover(int rem);

void rust_nla_warn_range_unsigned_neg(bool cond)
{
	WARN_ON_ONCE(cond);
}

void rust_nla_warn_range_unsigned_default(void)
{
	WARN_ON_ONCE(1);
}

void rust_nla_warn_range_signed_default(void)
{
	WARN_ON_ONCE(1);
}

void rust_nla_warn_int_range_default(void)
{
	WARN_ON(1);
}

void rust_nla_bug_on_type(bool cond)
{
	BUG_ON(cond);
}

void rust_nla_pr_invalid_len(int type)
{
	pr_warn_ratelimited("netlink: '%s': attribute type %d has an invalid length.\n",
			    current->comm, type);
}

void rust_nla_pr_invalid_len_range(int type)
{
	pr_warn_ratelimited("netlink: '%s': attribute type %d has an invalid length.\n",
			    current->comm, type);
}

void rust_nla_pr_leftover(int rem)
{
	pr_warn_ratelimited("netlink: %d bytes leftover after parsing attributes in process `%s'.\n",
			    rem, current->comm);
}

void nla_get_range_unsigned(const struct nla_policy *pt,
			    struct netlink_range_validation *range)
{
	rust_nla_get_range_unsigned(pt, range);
}

void nla_get_range_signed(const struct nla_policy *pt,
			  struct netlink_range_validation_signed *range)
{
	rust_nla_get_range_signed(pt, range);
}

int __nla_validate(const struct nlattr *head, int len, int maxtype,
		   const struct nla_policy *policy, unsigned int validate,
		   struct netlink_ext_ack *extack)
{
	return rust_nla_validate(head, len, maxtype, policy, validate, extack);
}
EXPORT_SYMBOL(__nla_validate);

int
nla_policy_len(const struct nla_policy *p, int n)
{
	return rust_nla_policy_len(p, n);
}
EXPORT_SYMBOL(nla_policy_len);

int __nla_parse(struct nlattr **tb, int maxtype,
		const struct nlattr *head, int len,
		const struct nla_policy *policy, unsigned int validate,
		struct netlink_ext_ack *extack)
{
	return rust_nla_parse(tb, maxtype, head, len, policy, validate, extack);
}
EXPORT_SYMBOL(__nla_parse);

struct nlattr *nla_find(const struct nlattr *head, int len, int attrtype)
{
	return rust_nla_find(head, len, attrtype);
}
EXPORT_SYMBOL(nla_find);

ssize_t nla_strscpy(char *dst, const struct nlattr *nla, size_t dstsize)
{
	if (dstsize == 0 || WARN_ON_ONCE(dstsize > U16_MAX))
		return -E2BIG;

	return rust_nla_strscpy(dst, nla, dstsize);
}
EXPORT_SYMBOL(nla_strscpy);

/**
 * nla_strdup - Copy string attribute payload into a newly allocated buffer
 * @nla: attribute to copy the string from
 * @flags: the type of memory to allocate (see kmalloc).
 *
 * Returns a pointer to the allocated buffer or NULL on error.
 */
char *nla_strdup(const struct nlattr *nla, gfp_t flags)
{
	size_t srclen = nla_len(nla);
	char *src = nla_data(nla), *dst;

	if (srclen > 0 && src[srclen - 1] == '\0')
		srclen--;

	dst = kmalloc(srclen + 1, flags);
	if (dst != NULL) {
		memcpy(dst, src, srclen);
		dst[srclen] = '\0';
	}
	return dst;
}
EXPORT_SYMBOL(nla_strdup);

int nla_memcpy(void *dest, const struct nlattr *src, int count)
{
	return rust_nla_memcpy(dest, src, count);
}
EXPORT_SYMBOL(nla_memcpy);

int nla_memcmp(const struct nlattr *nla, const void *data,
			     size_t size)
{
	return rust_nla_memcmp(nla, data, size);
}
EXPORT_SYMBOL(nla_memcmp);

int nla_strcmp(const struct nlattr *nla, const char *str)
{
	return rust_nla_strcmp(nla, str);
}
EXPORT_SYMBOL(nla_strcmp);

#ifdef CONFIG_NET
/**
 * __nla_reserve - reserve room for attribute on the skb
 * @skb: socket buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 *
 * Adds a netlink attribute header to a socket buffer and reserves
 * room for the payload but does not copy it.
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
struct nlattr *__nla_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
	struct nlattr *nla;

	nla = skb_put(skb, nla_total_size(attrlen));
	nla->nla_type = attrtype;
	nla->nla_len = nla_attr_size(attrlen);

	memset((unsigned char *) nla + nla->nla_len, 0, nla_padlen(attrlen));

	return nla;
}
EXPORT_SYMBOL(__nla_reserve);

/**
 * __nla_reserve_64bit - reserve room for attribute on the skb and align it
 * @skb: socket buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @padattr: attribute type for the padding
 *
 * Adds a netlink attribute header to a socket buffer and reserves
 * room for the payload but does not copy it. It also ensure that this
 * attribute will have a 64-bit aligned nla_data() area.
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
struct nlattr *__nla_reserve_64bit(struct sk_buff *skb, int attrtype,
				   int attrlen, int padattr)
{
	nla_align_64bit(skb, padattr);

	return __nla_reserve(skb, attrtype, attrlen);
}
EXPORT_SYMBOL(__nla_reserve_64bit);

/**
 * __nla_reserve_nohdr - reserve room for attribute without header
 * @skb: socket buffer to reserve room on
 * @attrlen: length of attribute payload
 *
 * Reserves room for attribute payload without a header.
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the payload.
 */
void *__nla_reserve_nohdr(struct sk_buff *skb, int attrlen)
{
	return skb_put_zero(skb, NLA_ALIGN(attrlen));
}
EXPORT_SYMBOL(__nla_reserve_nohdr);

/**
 * nla_reserve - reserve room for attribute on the skb
 * @skb: socket buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 *
 * Adds a netlink attribute header to a socket buffer and reserves
 * room for the payload but does not copy it.
 *
 * Returns NULL if the tailroom of the skb is insufficient to store
 * the attribute header and payload.
 */
struct nlattr *nla_reserve(struct sk_buff *skb, int attrtype, int attrlen)
{
	if (unlikely(skb_tailroom(skb) < nla_total_size(attrlen)))
		return NULL;

	return __nla_reserve(skb, attrtype, attrlen);
}
EXPORT_SYMBOL(nla_reserve);

/**
 * nla_reserve_64bit - reserve room for attribute on the skb and align it
 * @skb: socket buffer to reserve room on
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @padattr: attribute type for the padding
 *
 * Adds a netlink attribute header to a socket buffer and reserves
 * room for the payload but does not copy it. It also ensure that this
 * attribute will have a 64-bit aligned nla_data() area.
 *
 * Returns NULL if the tailroom of the skb is insufficient to store
 * the attribute header and payload.
 */
struct nlattr *nla_reserve_64bit(struct sk_buff *skb, int attrtype, int attrlen,
				 int padattr)
{
	size_t len;

	if (nla_need_padding_for_64bit(skb))
		len = nla_total_size_64bit(attrlen);
	else
		len = nla_total_size(attrlen);
	if (unlikely(skb_tailroom(skb) < len))
		return NULL;

	return __nla_reserve_64bit(skb, attrtype, attrlen, padattr);
}
EXPORT_SYMBOL(nla_reserve_64bit);

/**
 * nla_reserve_nohdr - reserve room for attribute without header
 * @skb: socket buffer to reserve room on
 * @attrlen: length of attribute payload
 *
 * Reserves room for attribute payload without a header.
 *
 * Returns NULL if the tailroom of the skb is insufficient to store
 * the attribute payload.
 */
void *nla_reserve_nohdr(struct sk_buff *skb, int attrlen)
{
	if (unlikely(skb_tailroom(skb) < NLA_ALIGN(attrlen)))
		return NULL;

	return __nla_reserve_nohdr(skb, attrlen);
}
EXPORT_SYMBOL(nla_reserve_nohdr);

/**
 * __nla_put - Add a netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
void __nla_put(struct sk_buff *skb, int attrtype, int attrlen,
			     const void *data)
{
	struct nlattr *nla;

	nla = __nla_reserve(skb, attrtype, attrlen);
	memcpy(nla_data(nla), data, attrlen);
}
EXPORT_SYMBOL(__nla_put);

/**
 * __nla_put_64bit - Add a netlink attribute to a socket buffer and align it
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 * @padattr: attribute type for the padding
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute header and payload.
 */
void __nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
		     const void *data, int padattr)
{
	struct nlattr *nla;

	nla = __nla_reserve_64bit(skb, attrtype, attrlen, padattr);
	memcpy(nla_data(nla), data, attrlen);
}
EXPORT_SYMBOL(__nla_put_64bit);

/**
 * __nla_put_nohdr - Add a netlink attribute without header
 * @skb: socket buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * The caller is responsible to ensure that the skb provides enough
 * tailroom for the attribute payload.
 */
void __nla_put_nohdr(struct sk_buff *skb, int attrlen, const void *data)
{
	void *start;

	start = __nla_reserve_nohdr(skb, attrlen);
	memcpy(start, data, attrlen);
}
EXPORT_SYMBOL(__nla_put_nohdr);

/**
 * nla_put - Add a netlink attribute to a socket buffer
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
 * the attribute header and payload.
 */
int nla_put(struct sk_buff *skb, int attrtype, int attrlen, const void *data)
{
	if (unlikely(skb_tailroom(skb) < nla_total_size(attrlen)))
		return -EMSGSIZE;

	__nla_put(skb, attrtype, attrlen, data);
	return 0;
}
EXPORT_SYMBOL(nla_put);

/**
 * nla_put_64bit - Add a netlink attribute to a socket buffer and align it
 * @skb: socket buffer to add attribute to
 * @attrtype: attribute type
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 * @padattr: attribute type for the padding
 *
 * Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
 * the attribute header and payload.
 */
int nla_put_64bit(struct sk_buff *skb, int attrtype, int attrlen,
		  const void *data, int padattr)
{
	size_t len;

	if (nla_need_padding_for_64bit(skb))
		len = nla_total_size_64bit(attrlen);
	else
		len = nla_total_size(attrlen);
	if (unlikely(skb_tailroom(skb) < len))
		return -EMSGSIZE;

	__nla_put_64bit(skb, attrtype, attrlen, data, padattr);
	return 0;
}
EXPORT_SYMBOL(nla_put_64bit);

/**
 * nla_put_nohdr - Add a netlink attribute without header
 * @skb: socket buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
 * the attribute payload.
 */
int nla_put_nohdr(struct sk_buff *skb, int attrlen, const void *data)
{
	if (unlikely(skb_tailroom(skb) < NLA_ALIGN(attrlen)))
		return -EMSGSIZE;

	__nla_put_nohdr(skb, attrlen, data);
	return 0;
}
EXPORT_SYMBOL(nla_put_nohdr);

/**
 * nla_append - Add a netlink attribute without header or padding
 * @skb: socket buffer to add attribute to
 * @attrlen: length of attribute payload
 * @data: head of attribute payload
 *
 * Returns -EMSGSIZE if the tailroom of the skb is insufficient to store
 * the attribute payload.
 */
int nla_append(struct sk_buff *skb, int attrlen, const void *data)
{
	if (unlikely(skb_tailroom(skb) < NLA_ALIGN(attrlen)))
		return -EMSGSIZE;

	skb_put_data(skb, data, attrlen);
	return 0;
}
EXPORT_SYMBOL(nla_append);
#endif
