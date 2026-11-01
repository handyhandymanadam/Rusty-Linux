// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/startup/efi-mixed.S (STUBH, Phase C): the EFI mixed-mode
//! (32-bit firmware, 64-bit kernel) entry and thunk code: `efi32_pe_entry`, `efi32_startup`
//! (builds a GDT and a 1:1 page table, switches to long mode), `__efi64_thunk` / `efi_enter32`
//! (call 32-bit EFI services from 64-bit code), `efi_is64`, and with CONFIG_EFI_HANDOVER_PROTOCOL
//! (`--cfg=efi_handover_protocol`) `efi32_stub_entry` and `efi64_stub_entry` (at +0x200).
//! Only built into the stub with CONFIG_EFI_MIXED.
//!
//! NOT BOOT-TESTED: mixed mode needs 32-bit EFI firmware (no IA32 OVMF here) and the handover
//! arms need a boot loader that uses the handover protocol. This file is therefore only
//! object-compared (rig/stubh/check.sh) and the Makefile keeps the original .S object for
//! CONFIG_EFI_MIXED / CONFIG_EFI_HANDOVER_PROTOCOL kernels (boot_rust_ok excludes both).
//!
//! The text is the .S verbatim (AT&T, `.code32`/`.code64` as in the .S). SYM_FUNC_START(_LOCAL/_NOALIGN)
//! / SYM_DATA* from linkage.h are written out. `RET` is `ret` (`ret; int3` with `--cfg=mitigation_sls`).
//! Constants are `const` operands checked against the headers by rig/stubh/consts_check.py;
//! `GDT_ENTRY(DESC_CODE64, 0, 0xfffff)` is given as the low and high 32 bits the .S uses.
//! TEST-GAP: everything (not wired, see above): no 32-bit EFI firmware here, no handover-protocol loader.
// C-HEADERS: linux/linkage.h asm/desc_defs.h asm/msr.h asm/page_types.h asm/pgtable_types.h asm/processor-flags.h asm/segment.h

use core::arch::global_asm;

/// `.balign CONFIG_FUNCTION_ALIGNMENT, 0x90`: the SYM_FUNC_START / SYM_CODE_START alignment (asm/linkage.h `__ALIGN`;
/// the `FUNCTION_PADDING` half is off in the stub, `-D__DISABLE_EXPORTS`). The Makefile exports the config value as
/// `STUBH_FUNCTION_ALIGNMENT`.
const FUNC_ALIGN: usize = parse_usize(env!("STUBH_FUNCTION_ALIGNMENT")); // C: CONFIG_FUNCTION_ALIGNMENT

const fn parse_usize(s: &str) -> usize {
    let b = s.as_bytes();
    assert!(!b.is_empty()); // an unset/empty build value must not become 0 silently
    let (mut i, mut n) = (0, 0);
    while i < b.len() {
        assert!(b[i] >= b'0' && b[i] <= b'9');
        n = n * 10 + (b[i] - b'0') as usize;
        i += 1;
    }
    n
}

const X86_CR0_PG_BIT: usize = 31; // C: X86_CR0_PG_BIT
const X86_CR4_PAE_BIT: usize = 5; // C: X86_CR4_PAE_BIT
const MSR_EFER: usize = 0xc000_0080; // C: MSR_EFER
const _EFER_LME: usize = 8; // C: _EFER_LME
const _PAGE_PRESENT: usize = 1 << 0; // C: _PAGE_PRESENT
const _PAGE_RW: usize = 1 << 1; // C: _PAGE_RW
const _PAGE_PSE: usize = 1 << 7; // C: _PAGE_PSE
const PAGE_SIZE: usize = 1 << 12; // C: PAGE_SIZE
const PMD_SIZE: usize = 1 << 21; // C: PMD_SIZE
/// GDT_ENTRY(DESC_CODE64, 0, 0xfffff) = 0x00af9b000000ffff: the 64-bit code segment descriptor appended to
/// the copied GDT, as the two 32-bit immediates the .S stores (checked against the macro).
const GDT_ENTRY_CODE64_LO: usize = 0x0000_ffff; // C: GDT_ENTRY(DESC_CODE64, 0, 0xfffff) & 0xffffffff
const GDT_ENTRY_CODE64_HI: usize = 0x00af_9b00; // C: GDT_ENTRY(DESC_CODE64, 0, 0xfffff) >> 32

// Kconfig switches the assembler text tests with `.if` (set from the stub's `--cfg` flags): everything below is ONE
// global_asm! block (separate blocks are not guaranteed to be emitted in source order, and a macro must precede its use).
// RET (arch/x86/include/asm/linkage.h with __DISABLE_EXPORTS) is `ret`, or `ret; int3` with CONFIG_MITIGATION_SLS.
const CONFIG_MITIGATION_SLS: usize = cfg!(mitigation_sls) as usize; // nocheck
const CONFIG_EFI_HANDOVER_PROTOCOL: usize = cfg!(efi_handover_protocol) as usize; // nocheck

global_asm!(
    r##"
	.macro	RET
	ret
	.if	{CONFIG_MITIGATION_SLS}
	int3
	.endif
	.endm

	.text
	.code32
	.if	{CONFIG_EFI_HANDOVER_PROTOCOL}	/* #ifdef CONFIG_EFI_HANDOVER_PROTOCOL */
	.globl	efi32_stub_entry
	.balign	{FUNC_ALIGN}, 0x90
efi32_stub_entry:
	call	1f
1:	popl	%ecx

	/* Clear BSS */
	xorl	%eax, %eax
	leal	(_bss - 1b)(%ecx), %edi
	leal	(_ebss - 1b)(%ecx), %ecx
	subl	%edi, %ecx
	shrl	$2, %ecx
	cld
	rep	stosl

	add	$0x4, %esp		/* Discard return address */
	movl	8(%esp), %ebx		/* struct boot_params pointer */
	jmp	efi32_startup
	.type	efi32_stub_entry, STT_FUNC
	.size	efi32_stub_entry, .-efi32_stub_entry
	.endif

/*
 * Called using a far call from __efi64_thunk() below, using the x86_64 SysV
 * ABI (except for R8/R9 which are inaccessible to 32-bit code - EAX/EBX are
 * used instead).  EBP+16 points to the arguments passed via the stack.
 *
 * The first argument (EDI) is a pointer to the boot service or protocol, to
 * which the remaining arguments are passed, each truncated to 32 bits.
 */
	.balign	{FUNC_ALIGN}, 0x90
efi_enter32:
	/*
	 * Convert x86-64 SysV ABI params to i386 ABI
	 */
	pushl	32(%ebp)	/* Up to 3 args passed via the stack */
	pushl	24(%ebp)
	pushl	16(%ebp)
	pushl	%ebx		/* R9 */
	pushl	%eax		/* R8 */
	pushl	%ecx
	pushl	%edx
	pushl	%esi

	/* Disable paging */
	movl	%cr0, %eax
	btrl	${X86_CR0_PG_BIT}, %eax
	movl	%eax, %cr0

	/* Disable long mode via EFER */
	movl	${MSR_EFER}, %ecx
	rdmsr
	btrl	${_EFER_LME}, %eax
	wrmsr

	call	*%edi

	/* We must preserve return value */
	movl	%eax, %edi

	call	efi32_enable_long_mode

	addl	$32, %esp
	movl	%edi, %eax
	lret
	.type	efi_enter32, STT_FUNC
	.size	efi_enter32, .-efi_enter32

	.code64
	.globl	__efi64_thunk
	.balign	{FUNC_ALIGN}, 0x90
__efi64_thunk:
	push	%rbp
	movl	%esp, %ebp
	push	%rbx

	/* Move args #5 and #6 into 32-bit accessible registers */
	movl	%r8d, %eax
	movl	%r9d, %ebx

	lcalll	*efi32_call(%rip)

	pop	%rbx
	pop	%rbp
	RET
	.type	__efi64_thunk, STT_FUNC
	.size	__efi64_thunk, .-__efi64_thunk

	.code32
	.balign	{FUNC_ALIGN}, 0x90
efi32_enable_long_mode:
	movl	%cr4, %eax
	btsl	$({X86_CR4_PAE_BIT}), %eax
	movl	%eax, %cr4

	movl	${MSR_EFER}, %ecx
	rdmsr
	btsl	${_EFER_LME}, %eax
	wrmsr

	/* Disable interrupts - the firmware's IDT does not work in long mode */
	cli

	/* Enable paging */
	movl	%cr0, %eax
	btsl	${X86_CR0_PG_BIT}, %eax
	movl	%eax, %cr0
	ret
	.type	efi32_enable_long_mode, STT_FUNC
	.size	efi32_enable_long_mode, .-efi32_enable_long_mode

/*
 * This is the common EFI stub entry point for mixed mode. It sets up the GDT
 * and page tables needed for 64-bit execution, after which it calls the
 * common 64-bit EFI entrypoint efi_stub_entry().
 *
 * Arguments:	0(%esp)	image handle
 * 		4(%esp)	EFI system table pointer
 *		%ebx	struct boot_params pointer (or NULL)
 *
 * Since this is the point of no return for ordinary execution, no registers
 * are considered live except for the function parameters. [Note that the EFI
 * stub may still exit and return to the firmware using the Exit() EFI boot
 * service.]
 */
	.balign	{FUNC_ALIGN}, 0x90
efi32_startup:
	movl	%esp, %ebp

	subl	$8, %esp
	sgdtl	(%esp)			/* Save GDT descriptor to the stack */
	movl	2(%esp), %esi		/* Existing GDT pointer */
	movzwl	(%esp), %ecx		/* Existing GDT limit */
	inc	%ecx			/* Existing GDT size */
	andl	$~7, %ecx		/* Ensure size is multiple of 8 */

	subl	%ecx, %esp		/* Allocate new GDT */
	andl	$~15, %esp		/* Realign the stack */
	movl	%esp, %edi		/* New GDT address */
	leal	7(%ecx), %eax		/* New GDT limit */
	pushw	%cx			/* Push 64-bit CS (for LJMP below) */
	pushl	%edi			/* Push new GDT address */
	pushw	%ax			/* Push new GDT limit */

	/* Copy GDT to the stack and add a 64-bit code segment at the end */
	movl	${GDT_ENTRY_CODE64_LO}, (%edi,%ecx)
	movl	${GDT_ENTRY_CODE64_HI}, 4(%edi,%ecx)
	shrl	$2, %ecx
	cld
	rep	movsl			/* Copy the firmware GDT */
	lgdtl	(%esp)			/* Switch to the new GDT */

	call	1f
1:	pop	%edi

	/* Record mixed mode entry */
	movb	$0x0, (efi_is64 - 1b)(%edi)

	/* Set up indirect far call to re-enter 32-bit mode */
	leal	(efi32_call - 1b)(%edi), %eax
	addl	%eax, (%eax)
	movw	%cs, 4(%eax)

	/* Disable paging */
	movl	%cr0, %eax
	btrl	${X86_CR0_PG_BIT}, %eax
	movl	%eax, %cr0

	/* Set up 1:1 mapping */
	leal	(pte - 1b)(%edi), %eax
	movl	$({_PAGE_PRESENT} | {_PAGE_RW} | {_PAGE_PSE}), %ecx
	leal	({_PAGE_PRESENT} | {_PAGE_RW})(%eax), %edx
2:	movl	%ecx, (%eax)
	addl	$8, %eax
	addl	${PMD_SIZE}, %ecx
	jnc	2b

	movl	${PAGE_SIZE}, %ecx
	.irpc	l, 0123
	movl	%edx, \l * 8(%eax)
	addl	%ecx, %edx
	.endr
	addl	%ecx, %eax
	movl	%edx, (%eax)
	movl	%eax, %cr3

	call	efi32_enable_long_mode

	/* Set up far jump to 64-bit mode (CS is already on the stack) */
	leal	(efi_stub_entry - 1b)(%edi), %eax
	movl	%eax, 2(%esp)

	movl	0(%ebp), %edi
	movl	4(%ebp), %esi
	movl	%ebx, %edx
	ljmpl	*2(%esp)
	.type	efi32_startup, STT_FUNC
	.size	efi32_startup, .-efi32_startup

/*
 * efi_status_t efi32_pe_entry(efi_handle_t image_handle,
 *			       efi_system_table_32_t *sys_table)
 */
	.globl	efi32_pe_entry
	.balign	{FUNC_ALIGN}, 0x90
efi32_pe_entry:
	pushl	%ebx				// save callee-save registers

	/* Check whether the CPU supports long mode */
	movl	$0x80000001, %eax		// assume extended info support
	cpuid
	btl	$29, %edx			// check long mode bit
	jnc	1f
	leal	8(%esp), %esp			// preserve stack alignment
	xor	%ebx, %ebx			// no struct boot_params pointer
	jmp	efi32_startup			// only ESP and EBX remain live
1:	movl	$0x80000003, %eax		// EFI_UNSUPPORTED
	popl	%ebx
	RET
	.type	efi32_pe_entry, STT_FUNC
	.size	efi32_pe_entry, .-efi32_pe_entry

	.if	{CONFIG_EFI_HANDOVER_PROTOCOL}	/* #ifdef CONFIG_EFI_HANDOVER_PROTOCOL */
	.org	efi32_stub_entry + 0x200
	.code64
	.globl	efi64_stub_entry
efi64_stub_entry:
	jmp	efi_handover_entry
	.type	efi64_stub_entry, STT_FUNC
	.size	efi64_stub_entry, .-efi64_stub_entry
	.endif

	.data
	.balign	8
efi32_call:
	.long	efi_enter32 - .
	.word	0x0
	.type	efi32_call, STT_OBJECT
	.size	efi32_call, .-efi32_call
	.globl	efi_is64
efi_is64:
	.byte 1
	.type	efi_is64, STT_OBJECT
	.size	efi_is64, .-efi_is64

	.bss
	.balign {PAGE_SIZE}
pte:
	.fill 6 * {PAGE_SIZE}, 1, 0
	.type	pte, STT_OBJECT
	.size	pte, .-pte
"##,
    FUNC_ALIGN = const FUNC_ALIGN,
    X86_CR0_PG_BIT = const X86_CR0_PG_BIT,
    MSR_EFER = const MSR_EFER,
    _EFER_LME = const _EFER_LME,
    X86_CR4_PAE_BIT = const X86_CR4_PAE_BIT,
    _PAGE_PRESENT = const _PAGE_PRESENT,
    _PAGE_RW = const _PAGE_RW,
    _PAGE_PSE = const _PAGE_PSE,
    PMD_SIZE = const PMD_SIZE,
    PAGE_SIZE = const PAGE_SIZE,
    GDT_ENTRY_CODE64_LO = const GDT_ENTRY_CODE64_LO,
    GDT_ENTRY_CODE64_HI = const GDT_ENTRY_CODE64_HI,
    CONFIG_MITIGATION_SLS = const CONFIG_MITIGATION_SLS,
    CONFIG_EFI_HANDOVER_PROTOCOL = const CONFIG_EFI_HANDOVER_PROTOCOL,
    options(att_syntax)
);
