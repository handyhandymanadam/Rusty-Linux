/* SPDX-License-Identifier: GPL-2.0
 *
 * lib/ bodies, verbatim from linux-6.18.49 apart from the kernel-isms that
 * do not exist in userspace. These are the ORACLES and are never edited to
 * agree with the Rust.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- lib/base64.c ---------------------------------------------------- */

static const char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int ref_base64_encode(const uint8_t *src, int srclen, char *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < srclen; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}
	while (bits < 0) {
		*cp++ = '=';
		bits += 2;
	}
	return cp - dst;
}

int ref_base64_decode(const char *src, int srclen, uint8_t *dst)
{
	uint32_t ac = 0;
	int bits = 0;
	int i;
	uint8_t *bp = dst;

	for (i = 0; i < srclen; i++) {
		const char *p = strchr(base64_table, src[i]);

		if (src[i] == '=') {
			ac = (ac << 6);
			bits += 6;
			if (bits >= 8)
				bits -= 8;
			continue;
		}
		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (uint8_t)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

/* ---- lib/memweight.c ------------------------------------------------- */

static inline unsigned int ref_hweight8(uint8_t w)
{
	return __builtin_popcount(w);
}

size_t ref_memweight(const void *ptr, size_t bytes)
{
	size_t ret = 0;
	size_t longs;
	const unsigned char *bitmap = ptr;

	for (; bytes > 0 && ((unsigned long)bitmap) % sizeof(long);
			bytes--, bitmap++)
		ret += ref_hweight8(*bitmap);

	longs = bytes / sizeof(long);
	if (longs) {
		size_t i;

		/* bitmap_weight() over `longs` longs */
		for (i = 0; i < longs; i++)
			ret += __builtin_popcountl(((const unsigned long *)bitmap)[i]);
		bytes -= longs * sizeof(long);
		bitmap += longs * sizeof(long);
	}
	for (; bytes > 0; bytes--, bitmap++)
		ret += ref_hweight8(*bitmap);

	return ret;
}

/* ---- lib/net_utils.c ------------------------------------------------- */

#define REF_ETH_ALEN 6
#define REF_MAC_ADDR_STR_LEN (3 * REF_ETH_ALEN - 1)

static int ref_isxdigit(int c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
	       (c >= 'A' && c <= 'F');
}

static int ref_hex_to_bin(unsigned char ch)
{
	unsigned char cu = ch & 0xdf;

	if (ch - '0' < 10)
		return ch - '0';
	if (cu - 'A' < 6)
		return cu - 'A' + 10;
	return -1;
}

bool ref_mac_pton(const char *s, uint8_t *mac)
{
	int i;

	if (strnlen(s, REF_MAC_ADDR_STR_LEN) < REF_MAC_ADDR_STR_LEN)
		return false;

	/* Don't dirty result unless string is valid MAC. */
	for (i = 0; i < REF_ETH_ALEN; i++) {
		if (!ref_isxdigit(s[i * 3]) || !ref_isxdigit(s[i * 3 + 1]))
			return false;
		if (i != REF_ETH_ALEN - 1 && s[i * 3 + 2] != ':')
			return false;
	}
	for (i = 0; i < REF_ETH_ALEN; i++)
		mac[i] = (ref_hex_to_bin(s[i * 3]) << 4) | ref_hex_to_bin(s[i * 3 + 1]);

	return true;
}

/* ---- lib/union_find.c ------------------------------------------------ */

struct ref_uf_node {
	struct ref_uf_node *parent;
	unsigned int rank;
};

struct ref_uf_node *ref_uf_find(struct ref_uf_node *node)
{
	struct ref_uf_node *parent;

	while (node->parent != node) {
		parent = node->parent;
		node->parent = parent->parent;
		node = parent;
	}
	return node;
}

void ref_uf_union(struct ref_uf_node *node1, struct ref_uf_node *node2)
{
	struct ref_uf_node *root1 = ref_uf_find(node1);
	struct ref_uf_node *root2 = ref_uf_find(node2);

	if (root1 == root2)
		return;

	if (root1->rank < root2->rank) {
		root1->parent = root2;
	} else if (root1->rank > root2->rank) {
		root2->parent = root1;
	} else {
		root2->parent = root1;
		root1->rank++;
	}
}

/* ---- lib/bcd.c ------------------------------------------------------- */

unsigned ref_bcd2bin(unsigned char val)
{
	return (val & 0x0f) + (val >> 4) * 10;
}

unsigned char ref_bin2bcd(unsigned val)
{
	const unsigned int t = (val * 103) >> 10;

	return (t << 4) | (val - t * 10);
}

/* ---- lib/win_minmax.c ------------------------------------------------ */

struct ref_minmax_sample { uint32_t t, v; };
struct ref_minmax { struct ref_minmax_sample s[3]; };

static uint32_t ref_minmax_reset(struct ref_minmax *m, uint32_t t, uint32_t meas)
{
	struct ref_minmax_sample val = { .t = t, .v = meas };

	m->s[2] = m->s[1] = m->s[0] = val;
	return m->s[0].v;
}

static uint32_t ref_minmax_subwin_update(struct ref_minmax *m, uint32_t win,
					 const struct ref_minmax_sample *val)
{
	uint32_t dt = val->t - m->s[0].t;

	if (dt > win) {
		m->s[0] = m->s[1];
		m->s[1] = m->s[2];
		m->s[2] = *val;
		if (val->t - m->s[0].t > win) {
			m->s[0] = m->s[1];
			m->s[1] = m->s[2];
			m->s[2] = *val;
		}
	} else if (m->s[1].t == m->s[0].t && dt > win / 4) {
		m->s[2] = m->s[1] = *val;
	} else if (m->s[2].t == m->s[1].t && dt > win / 2) {
		m->s[2] = *val;
	}
	return m->s[0].v;
}

uint32_t ref_minmax_running_max(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas)
{
	struct ref_minmax_sample val = { .t = t, .v = meas };

	if (val.v >= m->s[0].v || val.t - m->s[2].t > win)
		return ref_minmax_reset(m, t, meas);

	if (val.v >= m->s[1].v)
		m->s[2] = m->s[1] = val;
	else if (val.v >= m->s[2].v)
		m->s[2] = val;

	return ref_minmax_subwin_update(m, win, &val);
}

uint32_t ref_minmax_running_min(struct ref_minmax *m, uint32_t win, uint32_t t, uint32_t meas)
{
	struct ref_minmax_sample val = { .t = t, .v = meas };

	if (val.v <= m->s[0].v || val.t - m->s[2].t > win)
		return ref_minmax_reset(m, t, meas);

	if (val.v <= m->s[1].v)
		m->s[2] = m->s[1] = val;
	else if (val.v <= m->s[2].v)
		m->s[2] = val;

	return ref_minmax_subwin_update(m, win, &val);
}

/* ---- lib/crc/crc16.c ------------------------------------------------- */

#include "ref_crc16_table_generated.h"

uint16_t ref_crc16(uint16_t crc, const uint8_t *p, size_t len)
{
	while (len--)
		crc = (crc >> 8) ^ ref_crc16_table[(crc & 0xff) ^ *p++];
	return crc;
}

