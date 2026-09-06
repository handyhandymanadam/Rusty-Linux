#pragma once
/* Everything lib/iomap.c's own real hardware-access primitives (arch/x86/
 * include/asm/{io.h,shared/io.h}) reduce to, simulated in userspace:
 *
 * - PIO (inb/outb/...): a real x86 IN/OUT instruction needs iopl(3) or
 *   CAP_SYS_RAWIO and a real port to be meaningful -- neither available
 *   nor desirable in a differential harness. `pio_space[65536]` (defined
 *   in stubs.c, one instance shared by both the pristine reference and
 *   the port) stands in for the entire 16-bit port address space;
 *   PIO_MASK already restricts every real port number this file ever
 *   computes to that range.
 * - MMIO (readb/writeb/...): a real ioremap()'d cookie is, physically, a
 *   memory address a `mov` instruction reads or writes -- ordinary
 *   process memory behaves identically for everything this file's OWN
 *   logic does (dispatch, byte-swap, loop bookkeeping); it never
 *   depends on the access actually reaching a device. Plain pointer
 *   dereferences, not asm.
 * - insb/outsb/etc (arch's real `rep ins`/`rep outs`, a different thing
 *   from this file's own mmio_insb()/mmio_outsb()): simulated as a loop
 *   over the SAME `pio_space` array, matching "one fixed port, an
 *   advancing buffer" -- the property this differential's iowrite8_rep
 *   scenarios are actually checking.
 */
#include <linux/types.h>
#include <linux/printk.h>

extern unsigned char pio_space[65536];

static inline u8 inb(u16 port) { return pio_space[port]; }
static inline u16 inw(u16 port) { u16 v; __builtin_memcpy(&v, &pio_space[port], 2); return v; }
static inline u32 inl(u16 port) { u32 v; __builtin_memcpy(&v, &pio_space[port], 4); return v; }
static inline void outb(u8 val, u16 port) { pio_space[port] = val; }
static inline void outw(u16 val, u16 port) { __builtin_memcpy(&pio_space[port], &val, 2); }
static inline void outl(u32 val, u16 port) { __builtin_memcpy(&pio_space[port], &val, 4); }

static inline u8 readb(const volatile void *addr) { return *(const volatile u8 *)addr; }
static inline u16 readw(const volatile void *addr) { return *(const volatile u16 *)addr; }
static inline u32 readl(const volatile void *addr) { return *(const volatile u32 *)addr; }
static inline u64 readq(const volatile void *addr) { return *(const volatile u64 *)addr; }
static inline void writeb(u8 val, volatile void *addr) { *(volatile u8 *)addr = val; }
static inline void writew(u16 val, volatile void *addr) { *(volatile u16 *)addr = val; }
static inline void writel(u32 val, volatile void *addr) { *(volatile u32 *)addr = val; }
static inline void writeq(u64 val, volatile void *addr) { *(volatile u64 *)addr = val; }

#define __raw_readb readb
#define __raw_readw readw
#define __raw_readl readl
#define __raw_writeb writeb
#define __raw_writew writew
#define __raw_writel writel

static inline void insb(u16 port, void *dst, unsigned long count) {
	u8 *d = dst;
	while (count--) *d++ = inb(port);
}
static inline void insw(u16 port, void *dst, unsigned long count) {
	u16 *d = dst;
	while (count--) *d++ = inw(port);
}
static inline void insl(u16 port, void *dst, unsigned long count) {
	u32 *d = dst;
	while (count--) *d++ = inl(port);
}
static inline void outsb(u16 port, const void *src, unsigned long count) {
	const u8 *s = src;
	while (count--) outb(*s++, port);
}
static inline void outsw(u16 port, const void *src, unsigned long count) {
	const u16 *s = src;
	while (count--) outw(*s++, port);
}
static inline void outsl(u16 port, const void *src, unsigned long count) {
	const u32 *s = src;
	while (count--) outl(*s++, port);
}

static inline void iounmap(volatile void *addr) { (void)addr; }

static inline u16 swab16(u16 x) { return __builtin_bswap16(x); }
static inline u32 swab32(u32 x) { return __builtin_bswap32(x); }
static inline u64 swab64(u64 x) { return __builtin_bswap64(x); }
