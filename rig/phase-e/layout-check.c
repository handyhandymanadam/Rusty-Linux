/* One-off constant/layout check for the Phase E Rust files. NOT part of the build: copy to
 * src/linux/arch/x86/boot/startup/layout_check.c and compile it with the startup objects' own flags:
 *   kmake O=<build> arch/x86/boot/startup/layout_check.o
 * It fails to compile if a constant or offset the Rust mirrors differs from the kernel's. */
#include <linux/stddef.h>
#include <linux/types.h>
#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/trapnr.h>
#include <asm/x86_init.h>
#include <asm/bootparam.h>
#include <asm/setup.h>

/* gdt_idt_rs.rs */
_Static_assert(sizeof(gate_desc) == 16, "gate_desc size");
_Static_assert(offsetof(struct gate_struct, offset_low) == 0, "offset_low");
_Static_assert(offsetof(struct gate_struct, segment) == 2, "segment");
_Static_assert(offsetof(struct gate_struct, bits) == 4, "bits");
_Static_assert(offsetof(struct gate_struct, offset_middle) == 6, "offset_middle");
_Static_assert(offsetof(struct gate_struct, offset_high) == 8, "offset_high");
_Static_assert(offsetof(struct gate_struct, reserved) == 12, "reserved");
_Static_assert(sizeof(struct desc_ptr) == 10 && offsetof(struct desc_ptr, address) == 2, "desc_ptr");
_Static_assert(NUM_EXCEPTION_VECTORS == 32, "NUM_EXCEPTION_VECTORS");
_Static_assert(X86_TRAP_VC == 29, "X86_TRAP_VC");
_Static_assert(__KERNEL_CS == 0x10, "__KERNEL_CS");
_Static_assert(__KERNEL_DS == 0x18, "__KERNEL_DS");
_Static_assert(GDT_SIZE == 128, "GDT_SIZE");
_Static_assert(GATE_INTERRUPT == 0xE, "GATE_INTERRUPT");
_Static_assert(offsetof(struct gdt_page, gdt) == 0 && sizeof(((struct gdt_page *)0)->gdt) == GDT_SIZE, "gdt_page.gdt is first and GDT_SIZE bytes");
/* the 16-bit value of idt_bits{type=GATE_INTERRUPT,p=1}: read it from the object code (expect 0x8e00) */
unsigned short layout_idt_bits(void);
unsigned short layout_idt_bits(void)
{
	struct idt_bits b = { 0 };
	b.type = GATE_INTERRUPT;
	b.p = 1;
	return *(unsigned short *)&b;
}

/* platform_quirks_rs.rs */
_Static_assert(offsetof(struct x86_platform_ops, legacy) == 88, "x86_platform.legacy");
_Static_assert(offsetof(struct x86_platform_ops, set_legacy_features) == 112, "x86_platform.set_legacy_features");
_Static_assert(offsetof(struct x86_legacy_features, i8042) == 0, "legacy.i8042");
_Static_assert(offsetof(struct x86_legacy_features, rtc) == 4, "legacy.rtc");
_Static_assert(offsetof(struct x86_legacy_features, warm_reset) == 8, "legacy.warm_reset");
_Static_assert(offsetof(struct x86_legacy_features, reserve_bios_regions) == 16, "legacy.reserve_bios_regions");
_Static_assert(offsetof(struct x86_legacy_features, devices.pnpbios) == 20, "legacy.devices.pnpbios");
_Static_assert(sizeof(((struct x86_legacy_features *)0)->i8042) == 4 && sizeof(((struct x86_legacy_features *)0)->rtc) == 4, "int fields");
_Static_assert(X86_LEGACY_I8042_PLATFORM_ABSENT == 0 && X86_LEGACY_I8042_EXPECTED_PRESENT == 2, "i8042 enum");
_Static_assert(X86_SUBARCH_PC == 0 && X86_SUBARCH_XEN == 2 && X86_SUBARCH_INTEL_MID == 3 && X86_SUBARCH_CE4100 == 4, "subarch");
_Static_assert(offsetof(struct boot_params, hdr.hardware_subarch) == 0x23c, "hardware_subarch");

/* e820_rs.rs / e820_glue.c */
#include <asm/e820/types.h>
#include <asm/e820/api.h>
_Static_assert(sizeof(struct e820_entry) == 20, "sizeof(struct e820_entry)");
_Static_assert(sizeof(struct boot_e820_entry) == 20, "sizeof(struct boot_e820_entry)");
_Static_assert(offsetof(struct e820_entry, addr) == 0 && offsetof(struct e820_entry, size) == 8 && offsetof(struct e820_entry, type) == 16, "e820_entry fields");
_Static_assert(offsetof(struct boot_e820_entry, addr) == 0 && offsetof(struct boot_e820_entry, size) == 8 && offsetof(struct boot_e820_entry, type) == 16, "boot_e820_entry fields");
_Static_assert(offsetof(struct e820_table, nr_entries) == 0 && offsetof(struct e820_table, entries) == 4, "e820_table");
_Static_assert(sizeof(((struct e820_table *)0)->nr_entries) == 4, "nr_entries is u32");
_Static_assert(sizeof(enum e820_type) == 4 && (enum e820_type)-1 > 0, "enum e820_type is unsigned int");
_Static_assert(offsetof(struct boot_params, e820_entries) == 0x1e8 && offsetof(struct boot_params, e820_table) == 0x2d0 &&
	offsetof(struct boot_params, alt_mem_k) == 0x1e0 && offsetof(struct boot_params, screen_info.ext_mem_k) == 2, "boot_params e820 fields");
_Static_assert(sizeof(((struct boot_params *)0)->e820_entries) == 1 && sizeof(((struct boot_params *)0)->alt_mem_k) == 4 &&
	sizeof(((struct boot_params *)0)->screen_info.ext_mem_k) == 2, "boot_params e820 field widths");
