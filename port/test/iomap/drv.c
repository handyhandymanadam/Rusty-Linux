/* Differential test for lib/iomap.c -> lib/iomap_rs.rs.
 *
 * Scope: the 26 functions that moved to Rust (the IO_COND dispatch, the
 * byte-swap/64-bit hi-lo arithmetic, the repeat-loop bookkeeping,
 * ioport_map()/ioport_unmap()). NOT covered: pci_iounmap() (stayed in C
 * entirely -- see lib/iomap.c's own header comment for why: a ~512-type
 * kabi pin closure for one IO_COND branch that isn't worth it), and the
 * real hardware primitives underneath everything else (inb/outb/readb/
 * writeb/raw variants/insb/outsb/etc, all real, untouched,
 * arch-specific inline asm this port does not reimplement -- simulated
 * here via shim/linux/io.h, real enough to exercise this file's own
 * dispatch/arithmetic/loop logic, not real enough to test the asm itself).
 *
 * PIO vs MMIO vs "bad address" is chosen per scenario the same way
 * IO_COND itself decides it: an ioport_map()'d cookie for PIO, a real
 * heap pointer for MMIO (any real userspace allocation lands well above
 * PIO_RESERVED), and a small integer cast to a pointer for "bad".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;

/* Pristine reference (renamed, see run.sh). */
extern u32 ioread8_c_ref(const void *addr);
extern u32 ioread16_c_ref(const void *addr);
extern u32 ioread16be_c_ref(const void *addr);
extern u32 ioread32_c_ref(const void *addr);
extern u32 ioread32be_c_ref(const void *addr);
extern u64 __ioread64_lo_hi_c_ref(const void *addr);
extern u64 __ioread64_hi_lo_c_ref(const void *addr);
extern u64 __ioread64be_lo_hi_c_ref(const void *addr);
extern u64 __ioread64be_hi_lo_c_ref(const void *addr);
extern void iowrite8_c_ref(u8 val, void *addr);
extern void iowrite16_c_ref(u16 val, void *addr);
extern void iowrite16be_c_ref(u16 val, void *addr);
extern void iowrite32_c_ref(u32 val, void *addr);
extern void iowrite32be_c_ref(u32 val, void *addr);
extern void __iowrite64_lo_hi_c_ref(u64 val, void *addr);
extern void __iowrite64_hi_lo_c_ref(u64 val, void *addr);
extern void __iowrite64be_lo_hi_c_ref(u64 val, void *addr);
extern void __iowrite64be_hi_lo_c_ref(u64 val, void *addr);
extern void ioread8_rep_c_ref(const void *addr, void *dst, unsigned long count);
extern void ioread16_rep_c_ref(const void *addr, void *dst, unsigned long count);
extern void ioread32_rep_c_ref(const void *addr, void *dst, unsigned long count);
extern void iowrite8_rep_c_ref(void *addr, const void *src, unsigned long count);
extern void iowrite16_rep_c_ref(void *addr, const void *src, unsigned long count);
extern void iowrite32_rep_c_ref(void *addr, const void *src, unsigned long count);
extern void *ioport_map_c_ref(unsigned long port, unsigned int nr);
extern void ioport_unmap_c_ref(void *addr);

/* The port (Rust, real names). */
extern u32 ioread8(const void *addr);
extern u32 ioread16(const void *addr);
extern u32 ioread16be(const void *addr);
extern u32 ioread32(const void *addr);
extern u32 ioread32be(const void *addr);
extern u64 __ioread64_lo_hi(const void *addr);
extern u64 __ioread64_hi_lo(const void *addr);
extern u64 __ioread64be_lo_hi(const void *addr);
extern u64 __ioread64be_hi_lo(const void *addr);
extern void iowrite8(u8 val, void *addr);
extern void iowrite16(u16 val, void *addr);
extern void iowrite16be(u16 val, void *addr);
extern void iowrite32(u32 val, void *addr);
extern void iowrite32be(u32 val, void *addr);
extern void __iowrite64_lo_hi(u64 val, void *addr);
extern void __iowrite64_hi_lo(u64 val, void *addr);
extern void __iowrite64be_lo_hi(u64 val, void *addr);
extern void __iowrite64be_hi_lo(u64 val, void *addr);
extern void ioread8_rep(const void *addr, void *dst, unsigned long count);
extern void ioread16_rep(const void *addr, void *dst, unsigned long count);
extern void ioread32_rep(const void *addr, void *dst, unsigned long count);
extern void iowrite8_rep(void *addr, const void *src, unsigned long count);
extern void iowrite16_rep(void *addr, const void *src, unsigned long count);
extern void iowrite32_rep(void *addr, const void *src, unsigned long count);
extern void *ioport_map(unsigned long port, unsigned int nr);
extern void ioport_unmap(void *addr);

extern unsigned char pio_space[65536];

static unsigned checks, fails;
static void check(int ok, const char *what) {
	checks++;
	if (!ok) { fails++; fprintf(stderr, "MISMATCH: %s\n", what); }
}

static uint32_t rng_state;
static uint32_t xrand(void) {
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

#define PIO_OFFSET 0x10000UL
#define PIO_MASK   0x0ffffUL

static void *pio_cookie(u16 port) { return (void *)(PIO_OFFSET + port); }

/* Both the pristine reference and the port write through the SAME
 * simulated `pio_space[]` (inb/outb/etc have no "which space" parameter
 * to give them separate ones, matching the real kernel). So a PIO write
 * scenario snapshots the array, lets the C reference run and captures
 * its result, restores the snapshot, then lets the port run on the
 * identical starting state -- sequential, not interleaved, so each
 * side's own effect on the array is what gets compared, not whichever
 * ran second overwriting the first. */
static unsigned char pio_snapshot[65536];
static unsigned char pio_after_c[65536];
static void pio_save(void) { memcpy(pio_snapshot, pio_space, sizeof(pio_space)); }
static void pio_after_c_ref(void) { memcpy(pio_after_c, pio_space, sizeof(pio_space)); memcpy(pio_space, pio_snapshot, sizeof(pio_space)); }
static int pio_matches_after_rust(void) { return memcmp(pio_after_c, pio_space, sizeof(pio_space)) == 0; }

static void one_scenario(void) {
	u16 port = (u16)xrand();
	static unsigned char mmio_c[64], mmio_r[64];
	int use_mmio = xrand() & 1;
	void *addr_c = use_mmio ? (void *)mmio_c : pio_cookie(port);
	void *addr_r = use_mmio ? (void *)mmio_r : pio_cookie(port);

	if (use_mmio) {
		u32 seed = xrand();
		memcpy(mmio_c, &seed, 4); memcpy(mmio_r, &seed, 4);
		memset(mmio_c + 4, 0, sizeof(mmio_c) - 4);
		memset(mmio_r + 4, 0, sizeof(mmio_r) - 4);
	} else {
		unsigned char b = (unsigned char)xrand();
		memset(&pio_space[port & PIO_MASK], b, 8 <= 65536 - (port & PIO_MASK) ? 8 : 1);
	}

	switch (xrand() % 10) {
	case 0:
		check(ioread8_c_ref(addr_c) == ioread8(addr_r), "ioread8");
		break;
	case 1:
		check(ioread16_c_ref(addr_c) == ioread16(addr_r), "ioread16");
		check(ioread16be_c_ref(addr_c) == ioread16be(addr_r), "ioread16be");
		break;
	case 2:
		check(ioread32_c_ref(addr_c) == ioread32(addr_r), "ioread32");
		check(ioread32be_c_ref(addr_c) == ioread32be(addr_r), "ioread32be");
		break;
	case 3:
		check(__ioread64_lo_hi_c_ref(addr_c) == __ioread64_lo_hi(addr_r), "__ioread64_lo_hi");
		check(__ioread64_hi_lo_c_ref(addr_c) == __ioread64_hi_lo(addr_r), "__ioread64_hi_lo");
		check(__ioread64be_lo_hi_c_ref(addr_c) == __ioread64be_lo_hi(addr_r), "__ioread64be_lo_hi");
		check(__ioread64be_hi_lo_c_ref(addr_c) == __ioread64be_hi_lo(addr_r), "__ioread64be_hi_lo");
		break;
	case 4: {
		u8 v = (u8)xrand();
		if (!use_mmio) pio_save();
		iowrite8_c_ref(v, addr_c);
		if (!use_mmio) pio_after_c_ref();
		iowrite8(v, addr_r);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite8 buffer");
		break;
	}
	case 5: {
		u16 v = (u16)xrand();
		if (!use_mmio) pio_save();
		iowrite16_c_ref(v, addr_c); iowrite16be_c_ref(v, addr_c);
		if (!use_mmio) pio_after_c_ref();
		iowrite16(v, addr_r); iowrite16be(v, addr_r);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite16/16be buffer");
		break;
	}
	case 6: {
		u32 v = xrand();
		if (!use_mmio) pio_save();
		iowrite32_c_ref(v, addr_c); iowrite32be_c_ref(v, addr_c);
		if (!use_mmio) pio_after_c_ref();
		iowrite32(v, addr_r); iowrite32be(v, addr_r);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite32/32be buffer");
		break;
	}
	case 7: {
		u64 v = ((u64)xrand() << 32) | xrand();
		if (!use_mmio) pio_save();
		__iowrite64_lo_hi_c_ref(v, addr_c); __iowrite64_hi_lo_c_ref(v, addr_c);
		__iowrite64be_lo_hi_c_ref(v, addr_c); __iowrite64be_hi_lo_c_ref(v, addr_c);
		if (!use_mmio) pio_after_c_ref();
		__iowrite64_lo_hi(v, addr_r); __iowrite64_hi_lo(v, addr_r);
		__iowrite64be_lo_hi(v, addr_r); __iowrite64be_hi_lo(v, addr_r);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "__iowrite64* buffer");
		break;
	}
	case 8: {
		unsigned char dst_c[8], dst_r[8], src[8];
		unsigned n8 = 1 + (xrand() % 8);
		unsigned n16 = 1 + (xrand() % 4);
		unsigned i;
		for (i = 0; i < 8; i++) src[i] = (unsigned char)xrand();
		memset(dst_c, 0, 8); memset(dst_r, 0, 8);
		ioread8_rep_c_ref(addr_c, dst_c, n8); ioread8_rep(addr_r, dst_r, n8);
		check(memcmp(dst_c, dst_r, 8) == 0, "ioread8_rep dst");
		memset(dst_c, 0, 8); memset(dst_r, 0, 8);
		ioread16_rep_c_ref(addr_c, dst_c, n16); ioread16_rep(addr_r, dst_r, n16);
		check(memcmp(dst_c, dst_r, 8) == 0, "ioread16_rep dst");

		if (!use_mmio) pio_save();
		iowrite8_rep_c_ref(addr_c, src, n8);
		if (!use_mmio) pio_after_c_ref();
		iowrite8_rep(addr_r, src, n8);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite8_rep buffer");

		if (!use_mmio) pio_save();
		iowrite16_rep_c_ref(addr_c, src, n16);
		if (!use_mmio) pio_after_c_ref();
		iowrite16_rep(addr_r, src, n16);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite16_rep buffer");
		break;
	}
	case 9: {
		unsigned char dst_c[8], dst_r[8], src[8];
		unsigned n32 = 1 + (xrand() % 2);
		unsigned i;
		for (i = 0; i < 8; i++) src[i] = (unsigned char)xrand();
		memset(dst_c, 0, 8); memset(dst_r, 0, 8);
		ioread32_rep_c_ref(addr_c, dst_c, n32); ioread32_rep(addr_r, dst_r, n32);
		check(memcmp(dst_c, dst_r, 8) == 0, "ioread32_rep dst");

		if (!use_mmio) pio_save();
		iowrite32_rep_c_ref(addr_c, src, n32);
		if (!use_mmio) pio_after_c_ref();
		iowrite32_rep(addr_r, src, n32);
		check(use_mmio ? memcmp(mmio_c, mmio_r, sizeof(mmio_c)) == 0 : pio_matches_after_rust(), "iowrite32_rep buffer");
		break;
	}
	}
}

static void bad_address_scenario(void) {
	/* The "clearly bad" range, below PIO_OFFSET -- both sides must
	 * return the same documented sentinel and touch nothing. */
	void *bad = (void *)(uintptr_t)(xrand() % PIO_OFFSET);
	check(ioread8_c_ref(bad) == ioread8(bad), "bad address: ioread8 sentinel");
	check(ioread32_c_ref(bad) == ioread32(bad), "bad address: ioread32 sentinel");
	check(__ioread64_lo_hi_c_ref(bad) == __ioread64_lo_hi(bad), "bad address: __ioread64_lo_hi sentinel");
}

static void ioport_map_scenarios(void) {
	unsigned i;
	for (i = 0; i < 1000; i++) {
		unsigned long port = xrand() % (PIO_MASK + 2);
		void *rc = ioport_map_c_ref(port, 1);
		void *rr = ioport_map(port, 1);
		check(rc == rr, "ioport_map");
	}
	ioport_unmap_c_ref((void *)1);
	ioport_unmap((void *)1);
	check(1, "ioport_unmap: both are no-ops, ran without fault");
}

int main(int argc, char **argv) {
	long n = argc > 1 ? atol(argv[1]) : 50000;
	rng_state = argc > 2 ? (uint32_t)atol(argv[2]) : 0xC0FFEE;
	if (!rng_state) rng_state = 1;

	if (getenv("IOMAP_PROVE_CAN_FAIL")) {
		check(ioread8_c_ref((void *)pio_cookie(0)) == 12345, "POISON: deliberately wrong expectation");
		return fails ? 1 : 0;
	}

	ioport_map_scenarios();
	for (long i = 0; i < n; i++) {
		one_scenario();
		if (i % 37 == 0) bad_address_scenario();
	}

	printf("iomap: %ld scenarios, %u checks, %u fails\n", n, checks, fails);
	return fails ? 1 : 0;
}
