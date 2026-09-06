// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * The IO_COND dispatch (PIO vs MMIO), the byte-swap/64-bit-halving
 * arithmetic, the repeat-loop bookkeeping, and bad_io_access() all moved
 * to lib/iomap_rs.rs. pci_iounmap() did NOT move -- see below. Everything
 * else here is a one-line retained-C thunk around a real hardware-access
 * primitive that Rust cannot call directly, because none of them are real
 * linkable symbols:
 *
 *   - inb/inw/inl/outb/outw/outl (arch/x86/include/asm/shared/io.h):
 *     `static __always_inline`, a single `in`/`out` instruction each.
 *   - readb/readw/readl/readq/writeb/writew/writel/writeq
 *     (arch/x86/include/asm/io.h's build_mmio_read/write macros):
 *     `static inline`, a single `mov` with a `:"memory"` clobber -- a full
 *     compiler barrier, which matters for MMIO ordering.
 *   - __raw_readb/w/l, __raw_writeb/w/l: the SAME `mov`, but WITHOUT the
 *     `:"memory"` clobber (`#define __raw_readb __readb` etc.) -- a real,
 *     deliberate difference in how much reordering the compiler may do
 *     around the access, not a naming quirk.
 *   - insb/insw/insl/outsb/outsw/outsl (arch/x86/include/asm/io.h's
 *     BUILDIO macro): NOT bare instructions -- real logic
 *     (`cc_platform_has(CC_ATTR_GUEST_UNROLL_STRING_IO)`, a confidential-
 *     computing-guest runtime check deciding between a `rep ins`/`rep outs`
 *     string instruction and a manual per-element loop). This project's own
 *     lib/iomap.c has ITS OWN mmio_insb()/mmio_outsb() etc. for the MMIO
 *     side (a manual loop over __raw_readb()/__raw_writeb(), moved to
 *     Rust); these arch ones are the PIO side and are a different, more
 *     complex thing this port is not re-implementing.
 *
 * The STAC/CLAC precedent (lib/strncpy_from_user.c, logs/c-entry-rule.md)
 * asks "is this a bare instruction with no exception table, no goto" --
 * genuinely expressible directly in Rust via core::arch::asm!, as
 * flex_proportions_rs.rs did for arch_local_irq_save/restore. Every
 * primitive above passes that test on its own terms, but getting an
 * inline asm `:"memory"` clobber's exact reordering guarantee right, for
 * ~15 of them, on code whose only real-world failure mode is a hardware
 * ordering bug a differential harness cannot exercise (no real device
 * timing to get wrong against), is not a risk worth taking for what is,
 * per primitive, one saved function call. Thunked instead -- conservative
 * on purpose, matching this file's own hazard class as flagged going in.
 *
 * pci_iounmap() stays here ENTIRELY UNCHANGED, not thunked. Its own logic
 * is a single IO_COND check around a call to the real, already-exported
 * iounmap() (arch/x86/mm/ioremap.c) -- but its signature takes
 * `struct pci_dev *`, and kabi_export!()'s contract-verification path
 * needs every tag that signature's type-string references resolvable via
 * an explicit kabi_rule! pin (buildid_rs.rs's own module doc has the full
 * story). Captured and measured: pci_dev's own transitive closure is
 * ~512 types -- struct device's entire world. Porting one IO_COND branch
 * does not buy back that cost, so pci_iounmap() is left as a C entry that
 * "does more than call the Rust" on purpose (rig/guard-check.sh has this
 * function's own entry in rig/guard-except.txt for exactly this reason).
 * CONFIG_PCI is set on config-full only (config-fast has neither PCI nor
 * this function at all), so this is not even a cross-config question --
 * unlike buildid.c's, this one never had a config-fast shape to diverge
 * from.
 */

#include <linux/export.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/types.h>

#ifdef CONFIG_PCI
/* pci_iounmap() is the one function in this file that stayed C-side (see
 * this file's own header comment) -- so it keeps its own copy of the
 * dispatch macro and constants it needs, same names as the pristine C and
 * as lib/iomap_rs.rs's own equivalents, but a separate, static-scoped
 * definition: this is the only caller left of any of it in C.
 */
#ifndef HAVE_ARCH_PIO_SIZE
#define PIO_OFFSET	0x10000UL
#define PIO_MASK	0x0ffffUL
#define PIO_RESERVED	0x40000UL
#endif

static void bad_io_access(unsigned long port, const char *access)
{
	static int count = 10;
	if (count) {
		count--;
		WARN(1, KERN_ERR "Bad IO access at port %#lx (%s)\n", port, access);
	}
}

#define IO_COND(addr, is_pio, is_mmio) do {			\
	unsigned long port = (unsigned long __force)addr;	\
	if (port >= PIO_RESERVED) {				\
		is_mmio;					\
	} else if (port > PIO_OFFSET) {				\
		port &= PIO_MASK;				\
		is_pio;						\
	} else							\
		bad_io_access(port, #is_pio );			\
} while (0)
#endif /* CONFIG_PCI */

/* Forward-declared for the same reason as lib/strncpy_from_user.c's
 * rust_strncpy_uaccess_get_long(): config-full's -Wmissing-prototypes is
 * fatal (-Werror) and these symbols' only callers are Rust, via FFI.
 */
void rust_iomap_bad_io_access(u64 port, const char *what);
u8 rust_iomap_inb(u16 port);
u16 rust_iomap_inw(u16 port);
u32 rust_iomap_inl(u16 port);
void rust_iomap_outb(u8 val, u16 port);
void rust_iomap_outw(u16 val, u16 port);
void rust_iomap_outl(u32 val, u16 port);
u8 rust_iomap_readb(const void __iomem *addr);
u16 rust_iomap_readw(const void __iomem *addr);
u32 rust_iomap_readl(const void __iomem *addr);
u64 rust_iomap_readq(const void __iomem *addr);
void rust_iomap_writeb(u8 val, void __iomem *addr);
void rust_iomap_writew(u16 val, void __iomem *addr);
void rust_iomap_writel(u32 val, void __iomem *addr);
void rust_iomap_writeq(u64 val, void __iomem *addr);
u8 rust_iomap_raw_readb(const void __iomem *addr);
u16 rust_iomap_raw_readw(const void __iomem *addr);
u32 rust_iomap_raw_readl(const void __iomem *addr);
void rust_iomap_raw_writeb(u8 val, void __iomem *addr);
void rust_iomap_raw_writew(u16 val, void __iomem *addr);
void rust_iomap_raw_writel(u32 val, void __iomem *addr);
void rust_iomap_insb(u16 port, void *addr, unsigned long count);
void rust_iomap_insw(u16 port, void *addr, unsigned long count);
void rust_iomap_insl(u16 port, void *addr, unsigned long count);
void rust_iomap_outsb(u16 port, const void *addr, unsigned long count);
void rust_iomap_outsw(u16 port, const void *addr, unsigned long count);
void rust_iomap_outsl(u16 port, const void *addr, unsigned long count);

/* WARN() builds a __bug_table entry attributing itself to THIS file and
 * line -- see lib/iomap_rs.rs's own module doc for why this stays a
 * retained-C thunk, and for the one deliberate divergence (this and
 * pci_iounmap()'s own static bad_io_access() above now rate-limit
 * independently instead of sharing one counter).
 */
void rust_iomap_bad_io_access(u64 port, const char *what)
{
	static int count = 10;
	if (count) {
		count--;
		WARN(1, KERN_ERR "Bad IO access at port %#llx (%s)\n", port, what);
	}
}

u8 rust_iomap_inb(u16 port) { return inb(port); }
u16 rust_iomap_inw(u16 port) { return inw(port); }
u32 rust_iomap_inl(u16 port) { return inl(port); }
void rust_iomap_outb(u8 val, u16 port) { outb(val, port); }
void rust_iomap_outw(u16 val, u16 port) { outw(val, port); }
void rust_iomap_outl(u32 val, u16 port) { outl(val, port); }

u8 rust_iomap_readb(const void __iomem *addr) { return readb(addr); }
u16 rust_iomap_readw(const void __iomem *addr) { return readw(addr); }
u32 rust_iomap_readl(const void __iomem *addr) { return readl(addr); }
u64 rust_iomap_readq(const void __iomem *addr) { return readq(addr); }
void rust_iomap_writeb(u8 val, void __iomem *addr) { writeb(val, addr); }
void rust_iomap_writew(u16 val, void __iomem *addr) { writew(val, addr); }
void rust_iomap_writel(u32 val, void __iomem *addr) { writel(val, addr); }
void rust_iomap_writeq(u64 val, void __iomem *addr) { writeq(val, addr); }

u8 rust_iomap_raw_readb(const void __iomem *addr) { return __raw_readb(addr); }
u16 rust_iomap_raw_readw(const void __iomem *addr) { return __raw_readw(addr); }
u32 rust_iomap_raw_readl(const void __iomem *addr) { return __raw_readl(addr); }
void rust_iomap_raw_writeb(u8 val, void __iomem *addr) { __raw_writeb(val, addr); }
void rust_iomap_raw_writew(u16 val, void __iomem *addr) { __raw_writew(val, addr); }
void rust_iomap_raw_writel(u32 val, void __iomem *addr) { __raw_writel(val, addr); }

void rust_iomap_insb(u16 port, void *addr, unsigned long count) { insb(port, addr, count); }
void rust_iomap_insw(u16 port, void *addr, unsigned long count) { insw(port, addr, count); }
void rust_iomap_insl(u16 port, void *addr, unsigned long count) { insl(port, addr, count); }
void rust_iomap_outsb(u16 port, const void *addr, unsigned long count) { outsb(port, addr, count); }
void rust_iomap_outsw(u16 port, const void *addr, unsigned long count) { outsw(port, addr, count); }
void rust_iomap_outsl(u16 port, const void *addr, unsigned long count) { outsl(port, addr, count); }

#ifdef CONFIG_PCI
void pci_iounmap(struct pci_dev *dev, void __iomem *addr)
{
	IO_COND(addr, /* nothing */, iounmap(addr));
}
EXPORT_SYMBOL(pci_iounmap);
#endif /* CONFIG_PCI */
