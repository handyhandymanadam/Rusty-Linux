/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_NET_ADDRCONF_H
#define _SHIM_NET_ADDRCONF_H
#include <linux/types.h>

/* include/uapi/linux/socket.h / in.h / in6.h, unchanged shapes -- IS the
 * corpus in scope (ip_addr_string's 'S' family, real). */
#define AF_INET 2
#define AF_INET6 10

struct sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	unsigned short sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	u32 sin6_scope_id;
};

/* Real macro: include/net/ipv6.h, `cpu_to_be32(0x0FFFFFFF)` -- needs
 * asm/byteorder.h's cpu_to_be32 already included by this point (both are
 * pulled from vsprintf.c's own include list, addrconf.h after
 * byteorder.h). */
#define IPV6_FLOWINFO_MASK cpu_to_be32(0x0FFFFFFF)

/* Mirrors include/net/ipv6.h/include/linux/in6.h exactly, htonl folded to
 * a plain byteswap (this host and this project's only target are both
 * little-endian). */
static inline bool ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return ((unsigned long)(a->s6_addr32[0] | a->s6_addr32[1]) |
		(unsigned long)(a->s6_addr32[2] ^ __builtin_bswap32(0x0000ffff))) == 0UL;
}

static inline bool ipv6_addr_is_isatap(const struct in6_addr *addr)
{
	return (addr->s6_addr32[2] | __builtin_bswap32(0x02000000)) == __builtin_bswap32(0x02005EFE);
}

#endif
