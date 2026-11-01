// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	Generic address resolution entity
 *
 *	Authors:
 *	net_random Alan Cox
 *	net_ratelimit Andi Kleen
 *	in{4,6}_pton YOSHIFUJI Hideaki, Copyright (C)2006 USAGI/WIDE Project
 *
 *	Created by Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/ratelimit.h>
#include <linux/socket.h>

#include <net/sock.h>
#include <net/net_ratelimit.h>
#include <net/ipv6.h>

#include <asm/byteorder.h>
#include <linux/uaccess.h>

DEFINE_RATELIMIT_STATE(net_ratelimit_state, 5 * HZ, 10);
/*
 * All net warning printk()s should be guarded by this function.
 */
int net_ratelimit(void)
{
	return __ratelimit(&net_ratelimit_state);
}
EXPORT_SYMBOL(net_ratelimit);

/*
 * RUST PORT (net/core/utils.c, 6.18.49): in_aton(), xdigit2bin(), in4_pton() and in6_pton() (with their
 * EXPORT_SYMBOLs and the IN6PTON_* state bits) are in utils_rs.rs. Everything that touches sockets, net
 * devices, sk_buff or the rate limiter stays here. Upstream's file is installed as utils_norust.c for
 * CONFIG_RUST=n.
 */

static int inet4_pton(const char *src, u16 port_num,
		struct sockaddr_storage *addr)
{
	struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
	size_t srclen = strlen(src);

	if (srclen > INET_ADDRSTRLEN)
		return -EINVAL;

	if (in4_pton(src, srclen, (u8 *)&addr4->sin_addr.s_addr,
		     '\n', NULL) == 0)
		return -EINVAL;

	addr4->sin_family = AF_INET;
	addr4->sin_port = htons(port_num);

	return 0;
}

static int inet6_pton(struct net *net, const char *src, u16 port_num,
		struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
	const char *scope_delim;
	size_t srclen = strlen(src);

	if (srclen > INET6_ADDRSTRLEN)
		return -EINVAL;

	if (in6_pton(src, srclen, (u8 *)&addr6->sin6_addr.s6_addr,
		     '%', &scope_delim) == 0)
		return -EINVAL;

	if (ipv6_addr_type(&addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL &&
	    src + srclen != scope_delim && *scope_delim == '%') {
		struct net_device *dev;
		char scope_id[16];
		size_t scope_len = min_t(size_t, sizeof(scope_id) - 1,
					 src + srclen - scope_delim - 1);

		memcpy(scope_id, scope_delim + 1, scope_len);
		scope_id[scope_len] = '\0';

		dev = dev_get_by_name(net, scope_id);
		if (dev) {
			addr6->sin6_scope_id = dev->ifindex;
			dev_put(dev);
		} else if (kstrtouint(scope_id, 0, &addr6->sin6_scope_id)) {
			return -EINVAL;
		}
	}

	addr6->sin6_family = AF_INET6;
	addr6->sin6_port = htons(port_num);

	return 0;
}

/**
 * inet_pton_with_scope - convert an IPv4/IPv6 and port to socket address
 * @net: net namespace (used for scope handling)
 * @af: address family, AF_INET, AF_INET6 or AF_UNSPEC for either
 * @src: the start of the address string
 * @port: the start of the port string (or NULL for none)
 * @addr: output socket address
 *
 * Return zero on success, return errno when any error occurs.
 */
int inet_pton_with_scope(struct net *net, __kernel_sa_family_t af,
		const char *src, const char *port, struct sockaddr_storage *addr)
{
	u16 port_num;
	int ret = -EINVAL;

	if (port) {
		if (kstrtou16(port, 0, &port_num))
			return -EINVAL;
	} else {
		port_num = 0;
	}

	switch (af) {
	case AF_INET:
		ret = inet4_pton(src, port_num, addr);
		break;
	case AF_INET6:
		ret = inet6_pton(net, src, port_num, addr);
		break;
	case AF_UNSPEC:
		ret = inet4_pton(src, port_num, addr);
		if (ret)
			ret = inet6_pton(net, src, port_num, addr);
		break;
	default:
		pr_err("unexpected address family %d\n", af);
	}

	return ret;
}
EXPORT_SYMBOL(inet_pton_with_scope);

bool inet_addr_is_any(struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
		const struct sockaddr_in6 in6_any =
			{ .sin6_addr = IN6ADDR_ANY_INIT };

		if (!memcmp(in6->sin6_addr.s6_addr,
			    in6_any.sin6_addr.s6_addr, 16))
			return true;
	} else if (addr->ss_family == AF_INET) {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;

		if (in->sin_addr.s_addr == htonl(INADDR_ANY))
			return true;
	} else {
		pr_warn("unexpected address family %u\n", addr->ss_family);
	}

	return false;
}
EXPORT_SYMBOL(inet_addr_is_any);

void inet_proto_csum_replace4(__sum16 *sum, struct sk_buff *skb,
			      __be32 from, __be32 to, bool pseudohdr)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		csum_replace4(sum, from, to);
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr)
			skb->csum = ~csum_add(csum_sub(~(skb->csum),
						       (__force __wsum)from),
					      (__force __wsum)to);
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_add(csum_sub(csum_unfold(*sum),
						    (__force __wsum)from),
					   (__force __wsum)to));
}
EXPORT_SYMBOL(inet_proto_csum_replace4);

/**
 * inet_proto_csum_replace16 - update layer 4 header checksum field
 * @sum: Layer 4 header checksum field
 * @skb: sk_buff for the packet
 * @from: old IPv6 address
 * @to: new IPv6 address
 * @pseudohdr: True if layer 4 header checksum includes pseudoheader
 *
 * Update layer 4 header as per the update in IPv6 src/dst address.
 *
 * There is no need to update skb->csum in this function, because update in two
 * fields a.) IPv6 src/dst address and b.) L4 header checksum cancels each other
 * for skb->csum calculation. Whereas inet_proto_csum_replace4 function needs to
 * update skb->csum, because update in 3 fields a.) IPv4 src/dst address,
 * b.) IPv4 Header checksum and c.) L4 header checksum results in same diff as
 * L4 Header checksum for skb->csum calculation.
 */
void inet_proto_csum_replace16(__sum16 *sum, struct sk_buff *skb,
			       const __be32 *from, const __be32 *to,
			       bool pseudohdr)
{
	__be32 diff[] = {
		~from[0], ~from[1], ~from[2], ~from[3],
		to[0], to[1], to[2], to[3],
	};
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		*sum = csum_fold(csum_partial(diff, sizeof(diff),
				 ~csum_unfold(*sum)));
	} else if (pseudohdr)
		*sum = ~csum_fold(csum_partial(diff, sizeof(diff),
				  csum_unfold(*sum)));
}
EXPORT_SYMBOL(inet_proto_csum_replace16);

void inet_proto_csum_replace_by_diff(__sum16 *sum, struct sk_buff *skb,
				     __wsum diff, bool pseudohdr, bool ipv6)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		csum_replace_by_diff(sum, diff);
		if (skb->ip_summed == CHECKSUM_COMPLETE && pseudohdr && !ipv6)
			skb->csum = ~csum_sub(diff, skb->csum);
	} else if (pseudohdr) {
		*sum = ~csum_fold(csum_add(diff, csum_unfold(*sum)));
	}
}
EXPORT_SYMBOL(inet_proto_csum_replace_by_diff);
