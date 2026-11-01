/* One-off layout/constant check for the STUBE Rust files. NOT part of the build: copy to
 * src/linux/arch/x86/boot/compressed/layout_check.c and compile it with the stub's own flags:
 *   kmake O=<build> arch/x86/boot/compressed/layout_check.o
 * It fails to compile if a constant or offset the Rust mirrors differs from the kernel's. */
#include <linux/stddef.h>
#include <asm/trap_pf.h>
#include <asm/segment.h>
#include <asm/trapnr.h>
#include "misc.h"
#include <asm/bootparam.h>
#include <asm/e820/types.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <linux/pgtable.h>
#include <asm/init.h>
#include <asm/ptrace.h>
#define _SETUP
#include <asm/setup.h>
#undef _SETUP

/* idt_64_rs.rs */
_Static_assert(sizeof(gate_desc) == 16, "gate_desc size");
_Static_assert(offsetof(struct gate_struct, offset_low) == 0, "offset_low");
_Static_assert(offsetof(struct gate_struct, segment) == 2, "segment");
_Static_assert(offsetof(struct gate_struct, bits) == 4, "bits");
_Static_assert(offsetof(struct gate_struct, offset_middle) == 6, "offset_middle");
_Static_assert(offsetof(struct gate_struct, offset_high) == 8, "offset_high");
_Static_assert(offsetof(struct gate_struct, reserved) == 12, "reserved");
_Static_assert(sizeof(struct desc_ptr) == 10 && offsetof(struct desc_ptr, address) == 2, "desc_ptr");
_Static_assert(BOOT_IDT_ENTRIES == 32, "BOOT_IDT_ENTRIES");
_Static_assert(X86_TRAP_PF == 14 && X86_TRAP_NMI == 2 && X86_TRAP_VC == 29, "vectors");
_Static_assert(__KERNEL_CS == 0x10, "__KERNEL_CS");
_Static_assert(GATE_TRAP == 0xF, "GATE_TRAP");
/* the 16-bit value of idt_bits{type=GATE_TRAP,p=1}: read it from the object code (expect 0x8f00) */
unsigned short layout_idt_bits(void)
{
	struct idt_bits b = { 0 };
	b.type = GATE_TRAP;
	b.p = 1;
	return *(unsigned short *)&b;
}

/* pgtable_64_rs.rs */
_Static_assert(TRAMPOLINE_32BIT_SIZE == 8192 && TRAMPOLINE_32BIT_CODE_OFFSET == 4096 && TRAMPOLINE_32BIT_CODE_SIZE == 0xA0, "trampoline sizes");
_Static_assert(sizeof(struct boot_params) == 4096, "boot_params size");
_Static_assert(offsetof(struct boot_params, efi_info.efi_loader_signature) == 0x1c0, "efi_loader_signature");
_Static_assert(offsetof(struct boot_params, e820_entries) == 0x1e8, "e820_entries");
_Static_assert(offsetof(struct boot_params, sentinel) == 0x1ef, "sentinel");
_Static_assert(offsetof(struct boot_params, e820_table) == 0x2d0, "e820_table");
_Static_assert(sizeof(struct boot_e820_entry) == 20 && offsetof(struct boot_e820_entry, size) == 8 &&
	       offsetof(struct boot_e820_entry, type) == 16, "boot_e820_entry");
_Static_assert(E820_TYPE_RAM == 1, "E820_TYPE_RAM");
_Static_assert(X86_CR4_LA57 == (1UL << 12), "CR4.LA57");
#define sizeof_mbr(t, m) sizeof(((t *)0)->m)
#define SAVE(f, o, l) _Static_assert(offsetof(struct boot_params, f) == (o) && sizeof_mbr(struct boot_params, f) == (l), "to_save " #f)
SAVE(screen_info, 0x000, 64); SAVE(apm_bios_info, 0x040, 20); SAVE(tboot_addr, 0x058, 8); SAVE(ist_info, 0x060, 16);
SAVE(hd0_info, 0x080, 16); SAVE(hd1_info, 0x090, 16); SAVE(sys_desc_table, 0x0a0, 16); SAVE(olpc_ofw_header, 0x0b0, 16);
SAVE(efi_info, 0x1c0, 32); SAVE(alt_mem_k, 0x1e0, 4); SAVE(scratch, 0x1e4, 4); SAVE(e820_entries, 0x1e8, 1);
SAVE(eddbuf_entries, 0x1e9, 1); SAVE(edd_mbr_sig_buf_entries, 0x1ea, 1); SAVE(edd_mbr_sig_buffer, 0x290, 64);
SAVE(secure_boot, 0x1ec, 1); SAVE(hdr, 0x1f1, 123); SAVE(e820_table, 0x2d0, 2560); SAVE(eddbuf, 0xd00, 492);
SAVE(cc_blob_address, 0x13c, 4);
#ifndef CONFIG_AMD_MEM_ENCRYPT	/* with SEV these masks include the run-time variables sme_me_mask / physical_mask */
_Static_assert(_PAGE_TABLE_NOENC == 0x67, "_PAGE_TABLE_NOENC");
_Static_assert(PTE_PFN_MASK == 0x000ffffffffff000UL, "PTE_PFN_MASK");
_Static_assert(CR3_ADDR_MASK == 0x000ffffffffff000UL, "CR3_ADDR_MASK");
_Static_assert(__PAGE_KERNEL_LARGE_EXEC == 0x1e3, "__PAGE_KERNEL_LARGE_EXEC");
_Static_assert(_KERNPG_TABLE == 0x63, "_KERNPG_TABLE");
#endif

/* ident_map_64_rs.rs */
_Static_assert(PMD_SHIFT == 21 && PUD_SHIFT == 30 && P4D_SHIFT == 39, "shifts");
_Static_assert(PTRS_PER_PGD == 512 && PTRS_PER_PUD == 512 && PTRS_PER_PMD == 512 && PTRS_PER_PTE == 512, "ptrs");
_Static_assert(_PAGE_NOPTISHADOW == (1UL << 58), "_PAGE_NOPTISHADOW");
_Static_assert(_PAGE_PRESENT == 1 && _PAGE_RW == 2 && _PAGE_ACCESSED == 0x20 && _PAGE_DIRTY == 0x40 && _PAGE_PSE == 0x80 &&
	       _PAGE_GLOBAL == 0x100 && _PAGE_PROTNONE == 0x100, "page flag bits");
_Static_assert(BOOT_INIT_PGT_SIZE == 6 * 4096 && BOOT_PGT_SIZE_WARN == 28 * 4096 && BOOT_PGT_SIZE == 32 * 4096, "BOOT_PGT_*");
_Static_assert(COMMAND_LINE_SIZE == 2048, "COMMAND_LINE_SIZE");
_Static_assert(X86_PF_PROT == 1 && X86_PF_USER == 4 && X86_PF_RSVD == 8, "X86_PF_*");
_Static_assert(offsetof(struct pt_regs, ip) == 128, "pt_regs.ip");
_Static_assert(offsetof(struct boot_params, hdr.setup_data) == 0x250, "hdr.setup_data");
_Static_assert(sizeof(struct setup_data) == 16 && offsetof(struct setup_data, next) == 0 && offsetof(struct setup_data, len) == 12, "setup_data");
_Static_assert(sizeof(struct x86_mapping_info) == 56 && offsetof(struct x86_mapping_info, alloc_pgt_page) == 0 &&
	       offsetof(struct x86_mapping_info, free_pgt_page) == 8 && offsetof(struct x86_mapping_info, context) == 16 &&
	       offsetof(struct x86_mapping_info, page_flag) == 24 && offsetof(struct x86_mapping_info, offset) == 32 &&
	       offsetof(struct x86_mapping_info, direct_gbpages) == 40 && offsetof(struct x86_mapping_info, kernpg_flag) == 48, "x86_mapping_info");
_Static_assert(ENOMEM == 12, "ENOMEM");
