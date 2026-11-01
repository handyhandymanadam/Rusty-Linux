// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/head_64.S (STUBH, Phase C): the 64-bit boot stub's
//! entry code. `startup_32` (32-bit entry, address 0 of `.head.text`: ABI), `startup_64` (64-bit
//! entry at +0x200: ABI), `.Lrelocated` (clears bss, loads the stage-2 IDT, calls
//! initialize_identity_maps() and extract_kernel(), jumps to the decompressed kernel),
//! `.Lno_longmode`, `verify_cpu` (arch/x86/kernel/verify_cpu.S, `#include`d by the .S), the GDTs
//! (`gdt64`, `gdt`), `boot_idt_desc` / `boot_idt` (filled in by idt_64_rs.rs), the boot stack
//! and the `.pgtable` space. Nothing here can be debugged if it is wrong: a bad mode switch is a
//! silent reset, so the proof is the object-level comparison with the .S object (rig/stubh/check.sh)
//! BEFORE any boot.
//!
//! The text is the .S verbatim (AT&T syntax, comments kept). Mechanical expansions only:
//!   * `SYM_FUNC_START(x)`/`SYM_CODE_START` (linkage.h; `__ALIGN` is `.balign 16, 0x90` here):
//!     `.globl x ; .balign 16, 0x90 ; x:` .. `SYM_*_END`: `.type x, STT_FUNC|STT_NOTYPE ; .size x, .-x`;
//!     `_LOCAL` drops the `.globl`, `_NOALIGN` the `.balign`; `SYM_DATA*` likewise with STT_OBJECT and
//!     `SYM_DATA_END_LABEL(a, scope, b)` = `[.globl b] ; .type b, STT_OBJECT ; b: .type a, STT_OBJECT ; .size a, .-a`;
//!   * `__HEAD` = `.section ".head.text","ax"`; `rva(X)` = `((X) - startup_32)`;
//!   * `#ifdef CONFIG_AMD_MEM_ENCRYPT` / `CONFIG_RELOCATABLE` = `.if {CONFIG_*}` with the const operand 1 or 0 from
//!     `--cfg=amd_mem_encrypt` / `--cfg=relocatable` (so the text keeps the .S's order);
//!   * `RET` is `ret` (`ret; int3` with CONFIG_MITIGATION_SLS, `--cfg=mitigation_sls`);
//!   * verify_cpu.S: its `#ifndef __x86_64__` block (32-bit only, not assembled here) is not carried.
//! Numeric constants (segment selectors, CR4 bits, EFER, boot_params offsets, BOOT_* sizes, ...) are `const`
//! operands, checked against the headers by rig/stubh/consts_check.py. The three config-derived values the
//! headers compute (`LOAD_PHYSICAL_ADDR` from CONFIG_PHYSICAL_START/ALIGN, `REQUIRED_MASK0/1` from the
//! generated cpufeaturemasks.h) come in as environment variables `STUBH_*` set by the Makefile and become
//! const operands computed with the header's formulas (rig/stubh/consts_check.py checks them against the headers
//! of the build it is given, with the same environment).
//! TEST-GAP: (1) `.Lno_longmode` / the failing verify_cpu path is unreachable through a normal boot (the real-mode setup rejects CPUs
//! without long mode first; only a loader entering at startup_32 directly, e.g. kexec, gets there). (2) The 64-bit loader entry
//! `startup_64` at +0x200 is never entered DIRECTLY (QEMU `-kernel` uses the 32-bit protocol); the same code runs after startup_32's
//! `lret` (sabotage `movq %rsi,%r15` -> `%rdi` kills the boot). (3) OVMF/EFI boots do NOT run this file at all: the EFI stub decompresses
//! the kernel itself and jumps into it (libstub/x86-stub.c efi_decompress_kernel + enter_kernel), so "EFI 7/7" exercises the link, not this code.
//! (4) With CONFIG_AMD_MEM_ENCRYPT only the `sev_status == 0` side runs (get_sev_encryption_bit finds no SEV); `movl $1, sev_status`
//! and startup32_check_sev_cbit's real check need SEV. Proof for all of it: object identity with the .S, and bzImage/stub identity.
// C-HEADERS: linux/init.h linux/linkage.h asm/segment.h asm/boot.h asm/msr.h asm/processor-flags.h asm/asm-offsets.h asm/bootparam.h asm/desc_defs.h asm/trapnr.h asm/cpufeatures.h asm/cpufeaturemasks.h

use core::arch::global_asm;

const __BOOT_DS: usize = 0x18; // C: __BOOT_DS
const __BOOT_TSS: usize = 0x20; // C: __BOOT_TSS
const __KERNEL32_CS: usize = 0x08; // C: __KERNEL32_CS
const __KERNEL_CS: usize = 0x10; // C: __KERNEL_CS
const BP_SCRATCH: usize = 484; // C: BP_scratch
const BP_KERNEL_ALIGNMENT: usize = 560; // C: BP_kernel_alignment
const BP_INIT_SIZE: usize = 608; // C: BP_init_size
const X86_CR4_PAE: usize = 1 << 5; // C: X86_CR4_PAE
const X86_CR4_MCE: usize = 1 << 6; // C: X86_CR4_MCE
const X86_CR4_LA57: usize = 1 << 12; // C: X86_CR4_LA57
const BOOT_INIT_PGT_SIZE: usize = 6 * 4096; // C: BOOT_INIT_PGT_SIZE
const MSR_EFER: usize = 0xc000_0080; // C: MSR_EFER
const _EFER_LME: usize = 8; // C: _EFER_LME
const CR0_STATE: usize = 0x8005_0033; // C: CR0_STATE
const BOOT_IDT_ENTRIES: usize = 32; // C: BOOT_IDT_ENTRIES
const BOOT_STACK_SIZE: usize = 0x4000; // C: BOOT_STACK_SIZE
const BOOT_PGT_SIZE: usize = 32 * 4096; // C: BOOT_PGT_SIZE
const PAGE_SIZE: usize = 1 << 12; // C: PAGE_SIZE
const MSR_IA32_MISC_ENABLE: usize = 0x1a0; // C: MSR_IA32_MISC_ENABLE
const MSR_K7_HWCR: usize = 0xc001_0015; // C: MSR_K7_HWCR
const X86_FEATURE_XMM: usize = 25; // C: X86_FEATURE_XMM & 31
const X86_FEATURE_XMM2: usize = 26; // C: X86_FEATURE_XMM2 & 31

// Kconfig switches the assembler text tests with `.if` (set from the stub's `--cfg` flags): the whole file is ONE
// global_asm! block (separate blocks are not guaranteed to be emitted in source order, and a macro must precede its use).
const CONFIG_AMD_MEM_ENCRYPT: usize = cfg!(amd_mem_encrypt) as usize; // nocheck
const CONFIG_RELOCATABLE: usize = cfg!(relocatable) as usize; // nocheck
const CONFIG_MITIGATION_SLS: usize = cfg!(mitigation_sls) as usize; // nocheck

// Values the C headers compute from the configuration. The Makefile exports
//   STUBH_PHYSICAL_START=$(CONFIG_PHYSICAL_START)  STUBH_PHYSICAL_ALIGN=$(CONFIG_PHYSICAL_ALIGN)
//   STUBH_REQUIRED_MASK0/1 = the two numbers in arch/x86/include/generated/asm/cpufeaturemasks.h
// and the formulas are the headers' (asm/boot.h, uapi/asm/boot.h, cpufeaturemasks.h, verify_cpu.S).
const fn parse_num(s: &str) -> usize {
    let b = s.as_bytes();
    assert!(!b.is_empty()); // an unset/empty build value must not become 0 silently
    let (mut i, mut n, mut base) = (0, 0usize, 10usize);
    if b.len() > 2 && b[0] == b'0' && (b[1] == b'x' || b[1] == b'X') {
        i = 2;
        base = 16;
    }
    while i < b.len() {
        let c = b[i];
        let d = if c >= b'0' && c <= b'9' {
            c - b'0'
        } else if c >= b'a' && c <= b'f' {
            c - b'a' + 10
        } else {
            assert!(c >= b'A' && c <= b'F');
            c - b'A' + 10
        };
        assert!((d as usize) < base);
        n = n * base + d as usize;
        i += 1;
    }
    n
}
const CONFIG_PHYSICAL_START: usize = parse_num(env!("STUBH_PHYSICAL_START")); // C: CONFIG_PHYSICAL_START
const CONFIG_PHYSICAL_ALIGN: usize = parse_num(env!("STUBH_PHYSICAL_ALIGN")); // C: CONFIG_PHYSICAL_ALIGN
/// LOAD_PHYSICAL_ADDR ((CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & ~(CONFIG_PHYSICAL_ALIGN - 1))
const LOAD_PHYSICAL_ADDR: usize = (CONFIG_PHYSICAL_START + (CONFIG_PHYSICAL_ALIGN - 1)) & !(CONFIG_PHYSICAL_ALIGN - 1); // C: LOAD_PHYSICAL_ADDR
const REQUIRED_MASK0: usize = parse_num(env!("STUBH_REQUIRED_MASK0")); // C: REQUIRED_MASK0
const REQUIRED_MASK1: usize = parse_num(env!("STUBH_REQUIRED_MASK1")); // C: REQUIRED_MASK1
/// verify_cpu.S: #define SSE_MASK (REQUIRED_MASK0 & ((1<<(X86_FEATURE_XMM & 31)) | (1<<(X86_FEATURE_XMM2 & 31))))
const SSE_MASK: usize = REQUIRED_MASK0 & ((1 << X86_FEATURE_XMM) | (1 << X86_FEATURE_XMM2)); // C: (REQUIRED_MASK0 & ((1<<(X86_FEATURE_XMM & 31)) | (1<<(X86_FEATURE_XMM2 & 31))))

global_asm!(
    r##"
	.macro	RET
	ret
	.if	{CONFIG_MITIGATION_SLS}
	int3
	.endif
	.endm

/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory. [According to comments etc elsewhere on a compressed
 * kernel it will end up at 0x1000 + 1Mb I hope so as I assume this. - AC]
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in 
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86 
 * mode.
 */

/*
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */
	.code32
	.text



/*
 * Locally defined symbols should be marked hidden:
 */
	.hidden _bss
	.hidden _ebss
	.hidden _end

	.section ".head.text","ax"

/*
 * (cpp: #define rva(X) ((X) - startup_32).)  This macro gives the relative virtual address of X, i.e. the offset of X
 * from startup_32. This is the same as the link-time virtual address of X,
 * since startup_32 is at 0, but defining it this way tells the
 * assembler/linker that we do not want the actual run-time address of X. This
 * prevents the linker from trying to create unwanted run-time relocation
 * entries for the reference when the compressed kernel is linked as PIE.
 *
 * A reference X(%reg) will result in the link-time VA of X being stored with
 * the instruction, and a run-time R_X86_64_RELATIVE relocation entry that
 * adds the 64-bit base address where the kernel is loaded.
 *
 * Replacing it with (X-startup_32)(%reg) results in the offset being stored,
 * and no run-time relocation.
 *
 * The macro should be used as a displacement with a base register containing
 * the run-time address of startup_32 [i.e. rva(X)(%reg)], or as an immediate
 * [$ rva(X)].  (In this file rva(X) is written out as ((X) - startup_32).)
 *
 * This macro can only be used from within the .head.text section, since the
 * expression requires startup_32 to be in the same section as the code being
 * assembled.
 */

	.code32
	.globl	startup_32
	.balign	16, 0x90
startup_32:
	/*
	 * 32bit entry is 0 and it is ABI so immutable!
	 * If we come here directly from a bootloader,
	 * kernel(text+data+bss+brk) ramdisk, zero_page, command line
	 * all need to be under the 4G limit.
	 */
	cld
	cli

/*
 * Calculate the delta between where we were compiled to run
 * at and where we were actually loaded at.  This can only be done
 * with a short local call on x86.  Nothing  else will tell us what
 * address we are running at.  The reserved chunk of the real-mode
 * data at 0x1e4 (defined as a scratch field) are used as the stack
 * for this calculation. Only 4 bytes are needed.
 */
	leal	({BP_scratch}+4)(%esi), %esp
	call	1f
1:	popl	%ebp
	subl	$ ((1b) - startup_32), %ebp

	/* Load new GDT with the 64bit segments using 32bit descriptor */
	leal	((gdt) - startup_32)(%ebp), %eax
	movl	%eax, 2(%eax)
	lgdt	(%eax)

	/* Load segment registers with our descriptors */
	movl	${__BOOT_DS}, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

	/* Setup a stack and load CS from current GDT */
	leal	((boot_stack_end) - startup_32)(%ebp), %esp

	pushl	${__KERNEL32_CS}
	leal	((1f) - startup_32)(%ebp), %eax
	pushl	%eax
	lretl
1:

	/* Setup Exception handling for SEV-ES */
	.if {CONFIG_AMD_MEM_ENCRYPT}
	call	startup32_load_idt
	.endif

	/* Make sure cpu supports long mode. */
	call	verify_cpu
	testl	%eax, %eax
	jnz	.Lno_longmode

/*
 * Compute the delta between where we were compiled to run at
 * and where the code will actually run at.
 *
 * %ebp contains the address we are loaded at by the boot loader and %ebx
 * contains the address where we should move the kernel image temporarily
 * for safe in-place decompression.
 */

	.if {CONFIG_RELOCATABLE}
	movl	%ebp, %ebx
	movl	{BP_kernel_alignment}(%esi), %eax
	decl	%eax
	addl	%eax, %ebx
	notl	%eax
	andl	%eax, %ebx
	cmpl	${LOAD_PHYSICAL_ADDR}, %ebx
	jae	1f
	.endif
	movl	${LOAD_PHYSICAL_ADDR}, %ebx
1:

	/* Target address to relocate to for decompression */
	addl	{BP_init_size}(%esi), %ebx
	subl	$ ((_end) - startup_32), %ebx

/*
 * Prepare for entering 64 bit mode
 */

	/* Enable PAE mode */
	movl	%cr4, %eax
	orl	${X86_CR4_PAE}, %eax
	movl	%eax, %cr4

 /*
  * Build early 4G boot pagetable
  */
	/*
	 * If SEV is active then set the encryption mask in the page tables.
	 * This will ensure that when the kernel is copied and decompressed
	 * it will be done so encrypted.
	 */
	xorl	%edx, %edx
	.if {CONFIG_AMD_MEM_ENCRYPT}
	call	get_sev_encryption_bit
	xorl	%edx, %edx
	testl	%eax, %eax
	jz	1f
	subl	$32, %eax	/* Encryption bit is always above bit 31 */
	bts	%eax, %edx	/* Set encryption mask for page tables */
	/*
	 * Set MSR_AMD64_SEV_ENABLED_BIT in sev_status so that
	 * startup32_check_sev_cbit() will do a check. sev_enable() will
	 * initialize sev_status with all the bits reported by
	 * MSR_AMD_SEV_STATUS later, but only MSR_AMD64_SEV_ENABLED_BIT
	 * needs to be set for now.
	 */
	movl	$1, ((sev_status) - startup_32)(%ebp)
1:
	.endif

	/* Initialize Page tables to 0 */
	leal	((pgtable) - startup_32)(%ebx), %edi
	xorl	%eax, %eax
	movl	$({BOOT_INIT_PGT_SIZE}/4), %ecx
	rep	stosl

	/* Build Level 4 */
	leal	((pgtable + 0) - startup_32)(%ebx), %edi
	leal	0x1007 (%edi), %eax
	movl	%eax, 0(%edi)
	addl	%edx, 4(%edi)

	/* Build Level 3 */
	leal	((pgtable + 0x1000) - startup_32)(%ebx), %edi
	leal	0x1007(%edi), %eax
	movl	$4, %ecx
1:	movl	%eax, 0x00(%edi)
	addl	%edx, 0x04(%edi)
	addl	$0x00001000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Build Level 2 */
	leal	((pgtable + 0x2000) - startup_32)(%ebx), %edi
	movl	$0x00000183, %eax
	movl	$2048, %ecx
1:	movl	%eax, 0(%edi)
	addl	%edx, 4(%edi)
	addl	$0x00200000, %eax
	addl	$8, %edi
	decl	%ecx
	jnz	1b

	/* Enable the boot page tables */
	leal	((pgtable) - startup_32)(%ebx), %eax
	movl	%eax, %cr3

	/* Enable Long mode in EFER (Extended Feature Enable Register) */
	movl	${MSR_EFER}, %ecx
	rdmsr
	btsl	${_EFER_LME}, %eax
	wrmsr

	/* After gdt is loaded */
	xorl	%eax, %eax
	lldt	%ax
	movl    ${__BOOT_TSS}, %eax
	ltr	%ax

	.if {CONFIG_AMD_MEM_ENCRYPT}
	/* Check if the C-bit position is correct when SEV is active */
	call	startup32_check_sev_cbit
	.endif

	/*
	 * Setup for the jump to 64bit mode
	 *
	 * When the jump is performed we will be in long mode but
	 * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
	 * (and in turn EFER.LMA = 1).	To jump into 64bit mode we use
	 * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
	 * We place all of the values on our mini stack so lret can
	 * used to perform that far jump.
	 */
	leal	((startup_64) - startup_32)(%ebp), %eax
	pushl	${__KERNEL_CS}
	pushl	%eax

	/* Enter paged protected Mode, activating Long Mode */
	movl	${CR0_STATE}, %eax
	movl	%eax, %cr0

	/* Jump from 32bit compatibility mode into 64bit mode. */
	lret
	.type	startup_32, STT_FUNC
	.size	startup_32, .-startup_32

	.code64
	.org 0x200
	.globl	startup_64
	.balign	16, 0x90
startup_64:
	/*
	 * 64bit entry is 0x200 and it is ABI so immutable!
	 * We come here either from startup_32 or directly from a
	 * 64bit bootloader.
	 * If we come here from a bootloader, kernel(text+data+bss+brk),
	 * ramdisk, zero_page, command line could be above 4G.
	 * We depend on an identity mapped page table being provided
	 * that maps our entire kernel(text+data+bss+brk), zero page
	 * and command line.
	 */

	cld
	cli

	/* Setup data segments. */
	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	movl	%eax, %fs
	movl	%eax, %gs

	/*
	 * Compute the decompressed kernel start address.  It is where
	 * we were loaded at aligned to a 2M boundary. %rbp contains the
	 * decompressed kernel start address.
	 *
	 * If it is a relocatable kernel then decompress and run the kernel
	 * from load address aligned to 2MB addr, otherwise decompress and
	 * run the kernel from LOAD_PHYSICAL_ADDR
	 *
	 * We cannot rely on the calculation done in 32-bit mode, since we
	 * may have been invoked via the 64-bit entry point.
	 */

	/* Start with the delta to where the kernel will run at. */
	.if {CONFIG_RELOCATABLE}
	leaq	startup_32(%rip) /* - $startup_32 */, %rbp
	movl	{BP_kernel_alignment}(%rsi), %eax
	decl	%eax
	addq	%rax, %rbp
	notq	%rax
	andq	%rax, %rbp
	cmpq	${LOAD_PHYSICAL_ADDR}, %rbp
	jae	1f
	.endif
	movq	${LOAD_PHYSICAL_ADDR}, %rbp
1:

	/* Target address to relocate to for decompression */
	movl	{BP_init_size}(%rsi), %ebx
	subl	$ ((_end) - startup_32), %ebx
	addq	%rbp, %rbx

	/* Set up the stack */
	leaq	((boot_stack_end) - startup_32)(%rbx), %rsp

	/*
	 * At this point we are in long mode with 4-level paging enabled,
	 * but we might want to enable 5-level paging or vice versa.
	 *
	 * The problem is that we cannot do it directly. Setting or clearing
	 * CR4.LA57 in long mode would trigger #GP. So we need to switch off
	 * long mode and paging first.
	 *
	 * We also need a trampoline in lower memory to switch over from
	 * 4- to 5-level paging for cases when the bootloader puts the kernel
	 * above 4G, but didn't enable 5-level paging for us.
	 *
	 * The same trampoline can be used to switch from 5- to 4-level paging
	 * mode, like when starting 4-level paging kernel via kexec() when
	 * original kernel worked in 5-level paging mode.
	 *
	 * For the trampoline, we need the top page table to reside in lower
	 * memory as we don't have a way to load 64-bit values into CR3 in
	 * 32-bit mode.
	 */

	/* Make sure we have GDT with 32-bit code segment */
	leaq	gdt64(%rip), %rax
	addq	%rax, 2(%rax)
	lgdt	(%rax)

	/* Reload CS so IRET returns to a CS actually in the GDT */
	pushq	${__KERNEL_CS}
	leaq	.Lon_kernel_cs(%rip), %rax
	pushq	%rax
	lretq

.Lon_kernel_cs:
	/*
	 * RSI holds a pointer to a boot_params structure provided by the
	 * loader, and this needs to be preserved across C function calls. So
	 * move it into a callee saved register.
	 */
	movq	%rsi, %r15

	call	load_stage1_idt

	.if {CONFIG_AMD_MEM_ENCRYPT}
	/*
	 * Now that the stage1 interrupt handlers are set up, #VC exceptions from
	 * CPUID instructions can be properly handled for SEV-ES guests.
	 *
	 * For SEV-SNP, the CPUID table also needs to be set up in advance of any
	 * CPUID instructions being issued, so go ahead and do that now via
	 * sev_enable(), which will also handle the rest of the SEV-related
	 * detection/setup to ensure that has been done in advance of any dependent
	 * code. Pass the boot_params pointer as the first argument.
	 */
	movq	%r15, %rdi
	call	sev_enable
	.endif

	/* Preserve only the CR4 bits that must be preserved, and clear the rest */
	movq	%cr4, %rax
	andl	$({X86_CR4_PAE} | {X86_CR4_MCE} | {X86_CR4_LA57}), %eax
	movq	%rax, %cr4

	/*
	 * configure_5level_paging() updates the number of paging levels using
	 * a trampoline in 32-bit addressable memory if the current number does
	 * not match the desired number.
	 *
	 * Pass the boot_params pointer as the first argument. The second
	 * argument is the relocated address of the page table to use instead
	 * of the page table in trampoline memory (if required).
	 */
	movq	%r15, %rdi
	leaq	((top_pgtable) - startup_32)(%rbx), %rsi
	call	configure_5level_paging

	/* Zero EFLAGS */
	pushq	$0
	popfq

/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */
	leaq	(_bss-8)(%rip), %rsi
	leaq	((_bss-8) - startup_32)(%rbx), %rdi
	movl	$(_bss - startup_32), %ecx
	shrl	$3, %ecx
	std
	rep	movsq
	cld

	/*
	 * The GDT may get overwritten either during the copy we just did or
	 * during extract_kernel below. To avoid any issues, repoint the GDTR
	 * to the new copy of the GDT.
	 */
	leaq	((gdt64) - startup_32)(%rbx), %rax
	leaq	((gdt) - startup_32)(%rbx), %rdx
	movq	%rdx, 2(%rax)
	lgdt	(%rax)

/*
 * Jump to the relocated address.
 */
	leaq	((.Lrelocated) - startup_32)(%rbx), %rax
	jmp	*%rax
	.type	startup_64, STT_NOTYPE
	.size	startup_64, .-startup_64

	.text
.Lrelocated:

/*
 * Clear BSS (stack is currently empty)
 */
	xorl	%eax, %eax
	leaq    _bss(%rip), %rdi
	leaq    _ebss(%rip), %rcx
	subq	%rdi, %rcx
	shrq	$3, %rcx
	rep	stosq

	call	load_stage2_idt

	/* Pass boot_params to initialize_identity_maps() */
	movq	%r15, %rdi
	call	initialize_identity_maps

/*
 * Do the extraction, and jump to the new kernel..
 */
	/* pass struct boot_params pointer and output target address */
	movq	%r15, %rdi
	movq	%rbp, %rsi
	call	extract_kernel		/* returns kernel entry point in %rax */

/*
 * Jump to the decompressed kernel.
 */
	movq	%r15, %rsi
	jmp	*%rax
	.type	.Lrelocated, STT_FUNC
	.size	.Lrelocated, .-.Lrelocated

	.code32
.Lno_longmode:
	/* This isn't an x86-64 CPU, so hang intentionally, we cannot continue */
1:
	hlt
	jmp     1b
	.type	.Lno_longmode, STT_FUNC
	.size	.Lno_longmode, .-.Lno_longmode

	.globl	verify_cpu
	.balign	16, 0x90
verify_cpu:
	pushf				# Save caller passed flags
	push	$0			# Kill any dangerous flags
	popf


	movl	$0x0,%eax		# See if cpuid 1 is implemented
	cpuid
	cmpl	$0x1,%eax
	jb	.Lverify_cpu_no_longmode	# no cpuid 1

	xor	%di,%di
	cmpl	$0x68747541,%ebx	# AuthenticAMD
	jnz	.Lverify_cpu_noamd
	cmpl	$0x69746e65,%edx
	jnz	.Lverify_cpu_noamd
	cmpl	$0x444d4163,%ecx
	jnz	.Lverify_cpu_noamd
	mov	$1,%di			# cpu is from AMD
	jmp	.Lverify_cpu_check

.Lverify_cpu_noamd:
	cmpl	$0x756e6547,%ebx        # GenuineIntel?
	jnz	.Lverify_cpu_check
	cmpl	$0x49656e69,%edx
	jnz	.Lverify_cpu_check
	cmpl	$0x6c65746e,%ecx
	jnz	.Lverify_cpu_check

	# only call IA32_MISC_ENABLE when:
	# family > 6 || (family == 6 && model >= 0xd)
	movl	$0x1, %eax		# check CPU family and model
	cpuid
	movl	%eax, %ecx

	andl	$0x0ff00f00, %eax	# mask family and extended family
	shrl	$8, %eax
	cmpl	$6, %eax
	ja	.Lverify_cpu_clear_xd	# family > 6, ok
	jb	.Lverify_cpu_check	# family < 6, skip

	andl	$0x000f00f0, %ecx	# mask model and extended model
	shrl	$4, %ecx
	cmpl	$0xd, %ecx
	jb	.Lverify_cpu_check	# family == 6, model < 0xd, skip

.Lverify_cpu_clear_xd:
	movl	${MSR_IA32_MISC_ENABLE}, %ecx
	rdmsr
	btrl	$2, %edx		# clear MSR_IA32_MISC_ENABLE_XD_DISABLE
	jnc	.Lverify_cpu_check	# only write MSR if bit was changed
	wrmsr

.Lverify_cpu_check:
	movl    $0x1,%eax		# Does the cpu have what it takes
	cpuid
	andl	${REQUIRED_MASK0},%edx
	xorl	${REQUIRED_MASK0},%edx
	jnz	.Lverify_cpu_no_longmode

	movl    $0x80000000,%eax	# See if extended cpuid is implemented
	cpuid
	cmpl    $0x80000001,%eax
	jb      .Lverify_cpu_no_longmode	# no extended cpuid

	movl    $0x80000001,%eax	# Does the cpu have what it takes
	cpuid
	andl    ${REQUIRED_MASK1},%edx
	xorl    ${REQUIRED_MASK1},%edx
	jnz     .Lverify_cpu_no_longmode

.Lverify_cpu_sse_test:
	movl	$1,%eax
	cpuid
	andl	${SSE_MASK},%edx
	cmpl	${SSE_MASK},%edx
	je	.Lverify_cpu_sse_ok
	test	%di,%di
	jz	.Lverify_cpu_no_longmode	# only try to force SSE on AMD
	movl	${MSR_K7_HWCR},%ecx
	rdmsr
	btr	$15,%eax		# enable SSE
	wrmsr
	xor	%di,%di			# don't loop
	jmp	.Lverify_cpu_sse_test	# try again

.Lverify_cpu_no_longmode:
	popf				# Restore caller passed flags
	movl $1,%eax
	RET
.Lverify_cpu_sse_ok:
	popf				# Restore caller passed flags
	xorl %eax, %eax
	RET
	.type	verify_cpu, STT_FUNC
	.size	verify_cpu, .-verify_cpu

	.data
gdt64:
	.word	gdt_end - gdt - 1
	.quad   gdt - gdt64
	.type	gdt64, STT_OBJECT
	.size	gdt64, .-gdt64
	.balign	8
gdt:
	.word	gdt_end - gdt - 1
	.long	0
	.word	0
	.quad	0x00cf9a000000ffff	/* __KERNEL32_CS */
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
	.quad	0x0080890000000000	/* TS descriptor */
	.quad   0x0000000000000000	/* TS continued */
	.type	gdt_end, STT_OBJECT
gdt_end:
	.type	gdt, STT_OBJECT
	.size	gdt, .-gdt

	.globl	boot_idt_desc
boot_idt_desc:
	.word	boot_idt_end - boot_idt - 1
	.quad	0
	.type	boot_idt_desc, STT_OBJECT
	.size	boot_idt_desc, .-boot_idt_desc
	.balign 8
	.globl	boot_idt
boot_idt:
	.rept	{BOOT_IDT_ENTRIES}
	.quad	0
	.quad	0
	.endr
	.globl	boot_idt_end
	.type	boot_idt_end, STT_OBJECT
boot_idt_end:
	.type	boot_idt, STT_OBJECT
	.size	boot_idt, .-boot_idt

/*
 * Stack and heap for uncompression
 */
	.bss
	.balign 4
boot_stack:
	.fill {BOOT_STACK_SIZE}, 1, 0
	.balign 16
	.type	boot_stack_end, STT_OBJECT
boot_stack_end:
	.type	boot_stack, STT_OBJECT
	.size	boot_stack, .-boot_stack

/*
 * Space for page tables (not in .bss so not zeroed)
 */
	.section ".pgtable","aw",@nobits
	.balign 4096
pgtable:
	.fill {BOOT_PGT_SIZE}, 1, 0
	.type	pgtable, STT_OBJECT
	.size	pgtable, .-pgtable

/*
 * The page table is going to be used instead of page table in the trampoline
 * memory.
 */
top_pgtable:
	.fill {PAGE_SIZE}, 1, 0
	.type	top_pgtable, STT_OBJECT
	.size	top_pgtable, .-top_pgtable
"##,
    __BOOT_DS = const __BOOT_DS,
    __BOOT_TSS = const __BOOT_TSS,
    __KERNEL32_CS = const __KERNEL32_CS,
    __KERNEL_CS = const __KERNEL_CS,
    BP_scratch = const BP_SCRATCH,
    BP_kernel_alignment = const BP_KERNEL_ALIGNMENT,
    BP_init_size = const BP_INIT_SIZE,
    X86_CR4_PAE = const X86_CR4_PAE,
    X86_CR4_MCE = const X86_CR4_MCE,
    X86_CR4_LA57 = const X86_CR4_LA57,
    BOOT_INIT_PGT_SIZE = const BOOT_INIT_PGT_SIZE,
    MSR_EFER = const MSR_EFER,
    _EFER_LME = const _EFER_LME,
    CR0_STATE = const CR0_STATE,
    BOOT_IDT_ENTRIES = const BOOT_IDT_ENTRIES,
    BOOT_STACK_SIZE = const BOOT_STACK_SIZE,
    BOOT_PGT_SIZE = const BOOT_PGT_SIZE,
    PAGE_SIZE = const PAGE_SIZE,
    MSR_IA32_MISC_ENABLE = const MSR_IA32_MISC_ENABLE,
    MSR_K7_HWCR = const MSR_K7_HWCR,
    CONFIG_AMD_MEM_ENCRYPT = const CONFIG_AMD_MEM_ENCRYPT,
    CONFIG_RELOCATABLE = const CONFIG_RELOCATABLE,
    CONFIG_MITIGATION_SLS = const CONFIG_MITIGATION_SLS,
    LOAD_PHYSICAL_ADDR = const LOAD_PHYSICAL_ADDR,
    REQUIRED_MASK0 = const REQUIRED_MASK0,
    REQUIRED_MASK1 = const REQUIRED_MASK1,
    SSE_MASK = const SSE_MASK,
    options(att_syntax)
);
