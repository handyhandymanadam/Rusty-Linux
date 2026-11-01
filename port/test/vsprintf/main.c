/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Differential driver: REF's pristine pointer() vs RS's vsprintf_rs_pointer(),
 * for the %p corpus rows that actually moved to Rust this pass (module doc's
 * deferred list -- d/D/g/t/C/K/O/f/V/A -- is out of scope here; those forward
 * to identical-shaped C on both sides or are Rust-only bridges, not this
 * file's concern). 'S'/'s'/'B' (kallsyms) are exercised only for DISPATCH
 * correctness, via the shared deterministic stub in stubs.c -- see that
 * file's own comment for why real kallsyms resolution can't be tested here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* Mirrors lib/vsprintf.c's own struct printf_spec exactly (__packed,
 * sizeof == 8) -- can't #include vsprintf.c's internal definition, so
 * replicated here; vsprintf_rs.rs's own PrintfSpec is the same layout,
 * verified via its own static_assert. */
struct printf_spec {
	unsigned char flags;
	unsigned char base;
	short precision;
	int field_width;
} __attribute__((packed));

_Static_assert(sizeof(struct printf_spec) == 8, "printf_spec layout");

#define F_SIGN 1
#define F_LEFT 2
#define F_PLUS 4
#define F_SPACE 8
#define F_ZEROPAD 16
#define F_SMALL 32
#define F_SPECIAL 64

/* REF: pristine vsprintf.c, -Dstatic= exposes this. */
extern char *pointer(const char *fmt, char *buf, char *end, void *ptr, struct printf_spec spec);
/* RS: vsprintf_rs.rs's own exported entry point. */
extern char *vsprintf_rs_pointer(const char *fmt, char *buf, char *end, const void *ptr, struct printf_spec spec);

/* REF's own renamed globals + the RS-facing ones (stubs.c) -- kept in sync
 * explicitly before every case, see run_case()'s own comment. */
extern int ref_no_hash_pointers, ref_kptr_restrict, ref_debug_boot_weak_hash;
extern int ref_filled_random_ptr_key;
extern struct { unsigned long long key[2]; } ref_ptr_key;
extern _Bool no_hash_pointers, filled_random_ptr_key;
extern int debug_boot_weak_hash, kptr_restrict;
extern struct { unsigned long long key[2]; } ptr_key;

static unsigned long total, failed;

static void sync_globals(void)
{
	ref_no_hash_pointers = no_hash_pointers;
	ref_kptr_restrict = kptr_restrict;
	ref_debug_boot_weak_hash = debug_boot_weak_hash;
	ref_filled_random_ptr_key = filled_random_ptr_key;
	ref_ptr_key.key[0] = ptr_key.key[0];
	ref_ptr_key.key[1] = ptr_key.key[1];
}

/*
 * Runs one (fmt, ptr, spec) case at several buffer sizes (0, 1, a short
 * truncating size, and a size comfortably larger than anything this row
 * could produce), comparing both the returned "characters that would have
 * been written" delta and the actual bytes landed in the buffer up to
 * whichever is smaller (size, delta).
 */
static void run_case(const char *label, const char *fmt, void *ptr, struct printf_spec spec)
{
	size_t sizes[] = {0, 1, 3, 8, 256};
	size_t i;

	sync_globals();

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		size_t sz = sizes[i];
		char rbuf[256] = {0}, sbuf[256] = {0};
		char *rend = rbuf + (sz > 256 ? 256 : sz);
		char *send = sbuf + (sz > 256 ? 256 : sz);
		char *rret, *sret;
		long rdelta, sdelta;
		size_t cmplen;

		total++;

		rret = pointer(fmt, rbuf, rend, ptr, spec);
		sret = vsprintf_rs_pointer(fmt, sbuf, send, ptr, spec);

		rdelta = rret - rbuf;
		sdelta = sret - sbuf;

		if (rdelta != sdelta) {
			failed++;
			printf("MISMATCH(delta) %-10s fmt=%-8s size=%zu ref_delta=%ld rs_delta=%ld\n",
			       label, fmt, sz, rdelta, sdelta);
			continue;
		}

		cmplen = (size_t)rdelta < sz ? (size_t)rdelta : sz;
		if (memcmp(rbuf, sbuf, cmplen) != 0) {
			failed++;
			printf("MISMATCH(bytes) %-10s fmt=%-8s size=%zu delta=%ld ref=[%.*s] rs=[%.*s]\n",
			       label, fmt, sz, rdelta, (int)cmplen, rbuf, (int)cmplen, sbuf);
		}
	}
}

static uint64_t rngstate;
static uint64_t rnd(void)
{
	rngstate ^= rngstate << 13;
	rngstate ^= rngstate >> 7;
	rngstate ^= rngstate << 17;
	return rngstate;
}

/*
 * format_decode()'s own "qualifier:" section sets `spec->base = 10;`
 * UNCONDITIONALLY before its `lookup_state` dispatch, and the `'p'` row's
 * own table entry has `base == 0` (meaning "don't touch it") -- so by the
 * time pointer() is ever actually reached through the real call chain
 * (format_decode -> vsnprintf/vbin_printf -> pointer()), spec.base is
 * ALWAYS >= 10, never 0. `number()`'s `(spec.base as u32) - 1` relies on
 * that real precondition (matching the project's "trust internal
 * guarantees, don't defend against the impossible" rule) -- so the FIX
 * for a `default_spec()` that zero-initializes belongs here, in the test
 * harness's own setup, not in product code. Found by this harness's first
 * real run: omitting this crashed vsprintf_rs.rs's `number()` with a
 * `u32` subtract-overflow reachable only through an UNREALISTIC spec this
 * harness itself was constructing.
 */
static struct printf_spec default_spec(void)
{
	struct printf_spec s = {0};
	s.field_width = -1;
	s.precision = -1;
	s.base = 10;
	return s;
}

int main(int argc, char **argv)
{
	long runs = argc > 1 ? atol(argv[1]) : 2000;
	long i;

	rngstate = argc > 2 ? (uint64_t)atoll(argv[2]) : 20260906ULL;
	if (!rngstate)
		rngstate = 1;

	/* Put both arms' hash-pointer state on the real hash-computing path
	 * (not the "-EBUSY" fallback), deterministically, for the whole run. */
	filled_random_ptr_key = 1;
	no_hash_pointers = 0;
	debug_boot_weak_hash = 0;

	for (i = 0; i < runs; i++) {
		uint64_t v = rnd();
		void *ptr = (void *)(uintptr_t)(v | 0x1000); /* keep above PAGE_SIZE, non-NULL */
		struct printf_spec spec = default_spec();

		/* plain %p and %px */
		run_case("plain", "p", ptr, spec);
		run_case("x", "x", ptr, spec);

		/* %pe: ERR_PTR and non-ERR_PTR */
		run_case("e-normal", "e", ptr, spec);
		{
			void *errp = (void *)(intptr_t)-(long)(1 + (v % 130));
			run_case("e-errptr", "e", errp, spec);
		}

		/* symbol_string dispatch (kallsyms stubbed, see stubs.c) */
		run_case("S", "S", ptr, spec);
		run_case("s", "s", ptr, spec);
		run_case("SR", "SR", ptr, spec);
		run_case("B", "B", ptr, spec);
		run_case("Bb", "Bb", ptr, spec);
		run_case("Sb", "Sb", ptr, spec);

		/* resource/range */
		{
			struct resource_test {
				unsigned long long start, end;
				const char *name;
				unsigned long flags, desc;
				void *parent, *sibling, *child;
			} res = {
				.start = v & 0xffffff,
				.end = (v & 0xffffff) + (v % 4096),
				.flags = (v % 5 == 0) ? 0x100 : (v % 5 == 1) ? 0x200 :
					 (v % 5 == 2) ? 0x400 : (v % 5 == 3) ? 0x800 : 0x1000,
			};
			run_case("R", "R", &res, spec);
			run_case("r", "r", &res, spec);
		}
		{
			struct { unsigned long long start, end; } range = {
				.start = v & 0xffff, .end = (v & 0xffff) + 100,
			};
			run_case("ra", "ra", &range, spec);
		}

		/* hex_string / bitmap_string / bitmap_list_string */
		{
			unsigned char buf8[8];
			int k;
			for (k = 0; k < 8; k++)
				buf8[k] = (unsigned char)(v >> (k * 4));
			spec.field_width = 4;
			run_case("h", "h", buf8, spec);
			run_case("hC", "hC", buf8, spec);
			run_case("hD", "hD", buf8, spec);
			run_case("hN", "hN", buf8, spec);
			spec.field_width = 24;
			run_case("b", "b", buf8, spec);
			run_case("bl", "bl", buf8, spec);
			spec = default_spec();
		}

		/* mac_address_string */
		{
			unsigned char mac[6];
			int k;
			for (k = 0; k < 6; k++)
				mac[k] = (unsigned char)(v >> (k * 5));
			run_case("M", "M", mac, spec);
			run_case("m", "m", mac, spec);
			run_case("MF", "MF", mac, spec);
			run_case("MR", "MR", mac, spec);
		}

		/* IPv4/IPv6 */
		{
			unsigned char ip4[4];
			unsigned char ip6[16];
			int k;
			for (k = 0; k < 4; k++)
				ip4[k] = (unsigned char)(v >> (k * 7));
			for (k = 0; k < 16; k++)
				ip6[k] = (unsigned char)((v * (k + 1)) >> (k % 8));
			run_case("I4", "I4", ip4, spec);
			run_case("i4", "i4", ip4, spec);
			run_case("I4h", "I4h", ip4, spec);
			run_case("I4l", "I4l", ip4, spec);
			run_case("I4n", "I4n", ip4, spec);
			run_case("I4b", "I4b", ip4, spec);
			run_case("I6", "I6", ip6, spec);
			run_case("i6", "i6", ip6, spec);
			run_case("I6c", "I6c", ip6, spec);

			{
				struct sockaddr_in6_test {
					unsigned short family;
					unsigned short port;
					unsigned int flowinfo;
					unsigned char addr[16];
					unsigned int scope_id;
				} sa6 = {.family = 10, .port = (unsigned short)v, .flowinfo = (unsigned int)(v >> 3), .scope_id = (unsigned int)(v >> 9)};
				memcpy(sa6.addr, ip6, 16);
				run_case("ISpfc", "ISpfc", &sa6, spec);
				run_case("IS6c", "IS6c", &sa6, spec);
			}
			{
				struct sockaddr_in_test {
					unsigned short family;
					unsigned short port;
					unsigned int addr;
				} sa4 = {.family = 2, .port = (unsigned short)v, .addr = (unsigned int)v};
				run_case("ISp4", "ISp", &sa4, spec);
			}
		}

		/* escaped_string */
		{
			unsigned char ebuf[6] = {'a', 0, '\n', (unsigned char)v, 0x7f, 'z'};
			spec.field_width = 6;
			run_case("Ea", "Ea", ebuf, spec);
			run_case("Ec", "Ec", ebuf, spec);
			run_case("E-default", "E", ebuf, spec);
			spec = default_spec();
		}

		/* uuid_string */
		{
			unsigned char uuid[16];
			int k;
			for (k = 0; k < 16; k++)
				uuid[k] = (unsigned char)(v >> (k % 8));
			run_case("U", "U", uuid, spec);
			run_case("Ub", "Ub", uuid, spec);
			run_case("UB", "UB", uuid, spec);
			run_case("Ul", "Ul", uuid, spec);
			run_case("UL", "UL", uuid, spec);
		}

		/* netdev_bits / fourcc / address_val */
		{
			unsigned long long feat = v;
			run_case("NF", "NF", &feat, spec);
			unsigned int fourcc = (unsigned int)v;
			run_case("4cc", "4cc", &fourcc, spec);
			run_case("4ch", "4ch", &fourcc, spec);
			run_case("4chR", "4chR", &fourcc, spec);
			run_case("4cl", "4cl", &fourcc, spec);
			run_case("4cb", "4cb", &fourcc, spec);
			unsigned long long addr = v;
			run_case("ap", "ap", &addr, spec);
			run_case("ad", "ad", &addr, spec);
		}

		/* format_flags: 'g'/'v' (deterministic stub tables, stubs.c) */
		{
			unsigned long flags = v & 0x7;
			run_case("Gg", "Gg", &flags, spec);
			run_case("Gv", "Gv", &flags, spec);
		}

		/* string()/error()/default path via %u %k %<unknown> */
		{
			static const char *msgs[] = {"hello", "", "x", NULL};
			const char *s = msgs[v % 4];
			run_case("us", "us", &s, spec);
			run_case("ks", "ks", &s, spec);
			run_case("uz-einval", "uz", &s, spec);
		}

		/* NULL / error-value pointer through the plain %p path */
		run_case("plain-null", "p", NULL, spec);
		run_case("plain-errval", "p", (void *)(intptr_t)-5, spec);
	}

	printf("%lu cases, %lu mismatches\n", total, failed);
	return failed ? 1 : 0;
}
