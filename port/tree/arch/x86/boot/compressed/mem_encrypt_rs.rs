// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/compressed/mem_encrypt.S (STUBH, Phase C): AMD memory
//! encryption support for the 32-bit entry path (Tom Lendacky, AMD): `get_sev_encryption_bit`,
//! the #VC CPUID handler for the 32-bit IDT, `startup32_load_idt`, `startup32_check_sev_cbit`,
//! and (via #include in the .S) `sev_verify_cbit` from arch/x86/kernel/sev_verify_cbit.S, then
//! the `sme_me_mask` / `sev_status` / `sev_check_data` variables and the 32-bit IDT.
//!
//! The object is only part of the stub with CONFIG_AMD_MEM_ENCRYPT (the Makefile adds it under
//! that symbol; STUBH swaps it for this one with `--cfg=amd_mem_encrypt` set), so the
//! `#ifdef CONFIG_AMD_MEM_ENCRYPT` inside sev_verify_cbit.S is always true here and is not carried.
//! The assembly is the .S text verbatim (AT&T) with the linkage.h macros written out:
//!   SYM_FUNC_START(x)       .globl x ; .balign CONFIG_FUNCTION_ALIGNMENT, 0x90 ; x:      ...  SYM_FUNC_END: .type x, STT_FUNC ; .size
//!   SYM_FUNC_START_LOCAL(x) same without .globl;  SYM_CODE_*: same, .type STT_NOTYPE
//!   SYM_DATA(x, d)          .globl x ; x: d ; .type x, STT_OBJECT ; .size;  SYM_DATA_START_LOCAL: no .globl
//! `RET` is the arch/x86 linkage.h macro: in this stub (-D__DISABLE_EXPORTS, so never the return thunk)
//! it is `ret`, or `ret; int3` with CONFIG_MITIGATION_SLS (`--cfg=mitigation_sls`).
//! Numeric constants (MSR numbers, CR0/CR4 bits, segment, trap) are `const` operands, checked
//! against the headers by rig/stubh/consts_check.py.
//! TEST-GAP: needs SEV hardware for everything past the first CPUID test. Run here (non-SEV CPU, build-amd): get_sev_encryption_bit
//! (-> `.Lno_sev`; sabotage of that path hangs the boot), startup32_load_idt, startup32_check_sev_cbit (`sev_status == 0` exit).
//! NOT run: sev_es_req_cpuid and startup32_vc_handler (a #VC from CPUID), startup32_check_sev_cbit's RDRAND/CR0.PG compare and its
//! hlt loop, sev_verify_cbit's check (needs sme_me_mask != 0 and sev_status != 0) and its hlt loop. Object-identical to the .S for
//! those (default, SLS, FUNCTION_ALIGNMENT=32), nothing more.
// C-HEADERS: linux/linkage.h asm/processor-flags.h asm/msr.h asm/asm-offsets.h asm/segment.h asm/trapnr.h

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

const MSR_AMD64_SEV_ES_GHCB: usize = 0xc001_0130; // C: MSR_AMD64_SEV_ES_GHCB
const MSR_AMD64_SEV: usize = 0xc001_0131; // C: MSR_AMD64_SEV
const MSR_AMD64_SEV_ENABLED_BIT: usize = 0; // C: MSR_AMD64_SEV_ENABLED_BIT
const X86_CR0_PE: usize = 1 << 0; // C: X86_CR0_PE
const X86_CR0_PG: usize = 1 << 31; // C: X86_CR0_PG
const X86_CR4_PGE: usize = 1 << 7; // C: X86_CR4_PGE
const X86_TRAP_VC: usize = 29; // C: X86_TRAP_VC
const __KERNEL32_CS: usize = 0x08; // C: __KERNEL32_CS

// RET (arch/x86/include/asm/linkage.h with __DISABLE_EXPORTS) is `ret`, or `ret; int3` with CONFIG_MITIGATION_SLS (`--cfg=mitigation_sls`).
// Every Kconfig switch is tested with `.if`, so each file is ONE global_asm! block (separate blocks are not guaranteed to be
// emitted in source order, and a macro must precede its use).
const CONFIG_MITIGATION_SLS: usize = cfg!(mitigation_sls) as usize; // nocheck

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
	.globl	get_sev_encryption_bit
	.balign	{FUNC_ALIGN}, 0x90
get_sev_encryption_bit:
	push	%ebx

	movl	$0x80000000, %eax	/* CPUID to check the highest leaf */
	cpuid
	cmpl	$0x8000001f, %eax	/* See if 0x8000001f is available */
	jb	.Lno_sev

	/*
	 * Check for the SEV feature:
	 *   CPUID Fn8000_001F[EAX] - Bit 1
	 *   CPUID Fn8000_001F[EBX] - Bits 5:0
	 *     Pagetable bit position used to indicate encryption
	 */
	movl	$0x8000001f, %eax
	cpuid
	bt	$1, %eax		/* Check if SEV is available */
	jnc	.Lno_sev

	movl	${MSR_AMD64_SEV}, %ecx	/* Read the SEV MSR */
	rdmsr
	bt	${MSR_AMD64_SEV_ENABLED_BIT}, %eax	/* Check if SEV is active */
	jnc	.Lno_sev

	movl	%ebx, %eax
	andl	$0x3f, %eax		/* Return the encryption bit location */
	jmp	.Lsev_exit

.Lno_sev:
	xor	%eax, %eax

.Lsev_exit:
	pop	%ebx
	RET
	.type	get_sev_encryption_bit, STT_FUNC
	.size	get_sev_encryption_bit, .-get_sev_encryption_bit

/**
 * sev_es_req_cpuid - Request a CPUID value from the Hypervisor using
 *		      the GHCB MSR protocol
 *
 * @%eax:	Register to request (0=EAX, 1=EBX, 2=ECX, 3=EDX)
 * @%edx:	CPUID Function
 *
 * Returns 0 in %eax on success, non-zero on failure
 * %edx returns CPUID value on success
 */
	.balign	{FUNC_ALIGN}, 0x90
sev_es_req_cpuid:
	shll	$30, %eax
	orl     $0x00000004, %eax
	movl    ${MSR_AMD64_SEV_ES_GHCB}, %ecx
	wrmsr
	rep; vmmcall		# VMGEXIT
	rdmsr

	/* Check response */
	movl	%eax, %ecx
	andl	$0x3ffff000, %ecx	# Bits [12-29] MBZ
	jnz	2f

	/* Check return code */
	andl    $0xfff, %eax
	cmpl    $5, %eax
	jne	2f

	/* All good - return success */
	xorl	%eax, %eax
1:
	RET
2:
	movl	$-1, %eax
	jmp	1b
	.type	sev_es_req_cpuid, STT_NOTYPE
	.size	sev_es_req_cpuid, .-sev_es_req_cpuid

	.balign	{FUNC_ALIGN}, 0x90
startup32_vc_handler:
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx

	/* Keep CPUID function in %ebx */
	movl	%eax, %ebx

	/* Check if error-code == SVM_EXIT_CPUID */
	cmpl	$0x72, 16(%esp)
	jne	.Lfail

	movl	$0, %eax		# Request CPUID[fn].EAX
	movl	%ebx, %edx		# CPUID fn
	call	sev_es_req_cpuid	# Call helper
	testl	%eax, %eax		# Check return code
	jnz	.Lfail
	movl	%edx, 12(%esp)		# Store result

	movl	$1, %eax		# Request CPUID[fn].EBX
	movl	%ebx, %edx		# CPUID fn
	call	sev_es_req_cpuid	# Call helper
	testl	%eax, %eax		# Check return code
	jnz	.Lfail
	movl	%edx, 8(%esp)		# Store result

	movl	$2, %eax		# Request CPUID[fn].ECX
	movl	%ebx, %edx		# CPUID fn
	call	sev_es_req_cpuid	# Call helper
	testl	%eax, %eax		# Check return code
	jnz	.Lfail
	movl	%edx, 4(%esp)		# Store result

	movl	$3, %eax		# Request CPUID[fn].EDX
	movl	%ebx, %edx		# CPUID fn
	call	sev_es_req_cpuid	# Call helper
	testl	%eax, %eax		# Check return code
	jnz	.Lfail
	movl	%edx, 0(%esp)		# Store result

	/*
	 * Sanity check CPUID results from the Hypervisor. See comment in
	 * do_vc_no_ghcb() for more details on why this is necessary.
	 */

	/* Fail if SEV leaf not available in CPUID[0x80000000].EAX */
	cmpl    $0x80000000, %ebx
	jne     .Lcheck_sev
	cmpl    $0x8000001f, 12(%esp)
	jb      .Lfail
	jmp     .Ldone

.Lcheck_sev:
	/* Fail if SEV bit not set in CPUID[0x8000001f].EAX[1] */
	cmpl    $0x8000001f, %ebx
	jne     .Ldone
	btl     $1, 12(%esp)
	jnc     .Lfail

.Ldone:
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax

	/* Remove error code */
	addl	$4, %esp

	/* Jump over CPUID instruction */
	addl	$2, (%esp)

	iret
.Lfail:
	/* Send terminate request to Hypervisor */
	movl    $0x100, %eax
	xorl    %edx, %edx
	movl    ${MSR_AMD64_SEV_ES_GHCB}, %ecx
	wrmsr
	rep; vmmcall

	/* If request fails, go to hlt loop */
	hlt
	jmp .Lfail
	.type	startup32_vc_handler, STT_NOTYPE
	.size	startup32_vc_handler, .-startup32_vc_handler

/*
 * Write an IDT entry into boot32_idt
 *
 * Parameters:
 *
 * %eax:	Handler address
 * %edx:	Vector number
 * %ecx:	IDT address
 */
	.balign	{FUNC_ALIGN}, 0x90
startup32_set_idt_entry:
	/* IDT entry address to %ecx */
	leal	(%ecx, %edx, 8), %ecx

	/* Build IDT entry, lower 4 bytes */
	movl    %eax, %edx
	andl    $0x0000ffff, %edx		# Target code segment offset [15:0]
	orl	$({__KERNEL32_CS} << 16), %edx	# Target code segment selector

	/* Store lower 4 bytes to IDT */
	movl    %edx, (%ecx)

	/* Build IDT entry, upper 4 bytes */
	movl    %eax, %edx
	andl    $0xffff0000, %edx	# Target code segment offset [31:16]
	orl     $0x00008e00, %edx	# Present, Type 32-bit Interrupt Gate

	/* Store upper 4 bytes to IDT */
	movl    %edx, 4(%ecx)

	RET
	.type	startup32_set_idt_entry, STT_FUNC
	.size	startup32_set_idt_entry, .-startup32_set_idt_entry

	.globl	startup32_load_idt
	.balign	{FUNC_ALIGN}, 0x90
startup32_load_idt:
	push	%ebp
	push	%ebx

	call	1f
1:	pop	%ebp

	leal    (boot32_idt - 1b)(%ebp), %ebx

	/* #VC handler */
	leal    (startup32_vc_handler - 1b)(%ebp), %eax
	movl    ${X86_TRAP_VC}, %edx
	movl	%ebx, %ecx
	call    startup32_set_idt_entry

	/* Load IDT */
	leal	(boot32_idt_desc - 1b)(%ebp), %ecx
	movl	%ebx, 2(%ecx)
	lidt    (%ecx)

	pop	%ebx
	pop	%ebp
	RET
	.type	startup32_load_idt, STT_FUNC
	.size	startup32_load_idt, .-startup32_load_idt

/*
 * Check for the correct C-bit position when the startup_32 boot-path is used.
 *
 * The check makes use of the fact that all memory is encrypted when paging is
 * disabled. The function creates 64 bits of random data using the RDRAND
 * instruction. RDRAND is mandatory for SEV guests, so always available. If the
 * hypervisor violates that the kernel will crash right here.
 *
 * The 64 bits of random data are stored to a memory location and at the same
 * time kept in the %eax and %ebx registers. Since encryption is always active
 * when paging is off the random data will be stored encrypted in main memory.
 *
 * Then paging is enabled. When the C-bit position is correct all memory is
 * still mapped encrypted and comparing the register values with memory will
 * succeed. An incorrect C-bit position will map all memory unencrypted, so that
 * the compare will use the encrypted random data and fail.
 */
	.globl	startup32_check_sev_cbit
	.balign	{FUNC_ALIGN}, 0x90
startup32_check_sev_cbit:
	pushl	%ebx
	pushl	%ebp

	call	0f
0:	popl	%ebp

	/* Check for non-zero sev_status */
	movl	(sev_status - 0b)(%ebp), %eax
	testl	%eax, %eax
	jz	4f

	/*
	 * Get two 32-bit random values - Don't bail out if RDRAND fails
	 * because it is better to prevent forward progress if no random value
	 * can be gathered.
	 */
1:	rdrand	%eax
	jnc	1b
2:	rdrand	%ebx
	jnc	2b

	/* Store to memory and keep it in the registers */
	leal	(sev_check_data - 0b)(%ebp), %ebp
	movl	%eax, 0(%ebp)
	movl	%ebx, 4(%ebp)

	/* Enable paging to see if encryption is active */
	movl	%cr0, %edx			 /* Backup %cr0 in %edx */
	movl	$({X86_CR0_PG} | {X86_CR0_PE}), %ecx /* Enable Paging and Protected mode */
	movl	%ecx, %cr0

	cmpl	%eax, 0(%ebp)
	jne	3f
	cmpl	%ebx, 4(%ebp)
	jne	3f

	movl	%edx, %cr0	/* Restore previous %cr0 */

	jmp	4f

3:	/* Check failed - hlt the machine */
	hlt
	jmp	3b

4:
	popl	%ebp
	popl	%ebx
	RET
	.type	startup32_check_sev_cbit, STT_FUNC
	.size	startup32_check_sev_cbit, .-startup32_check_sev_cbit

	.code64

/* ---- arch/x86/kernel/sev_verify_cbit.S (#included here by the .S) ---- */
/*
 *	sev_verify_cbit.S - Code for verification of the C-bit position reported
 *			    by the Hypervisor when running with SEV enabled.
 *
 *	Copyright (c) 2020  Joerg Roedel (jroedel@suse.de)
 *
 * sev_verify_cbit() is called before switching to a new long-mode page-table
 * at boot.
 *
 * Verify that the C-bit position is correct by writing a random value to
 * an encrypted memory location while on the current page-table. Then it
 * switches to the new page-table to verify the memory content is still the
 * same. After that it switches back to the current page-table and when the
 * check succeeded it returns. If the check failed the code invalidates the
 * stack pointer and goes into a hlt loop. The stack-pointer is invalidated to
 * make sure no interrupt or exception can get the CPU out of the hlt loop.
 *
 * New page-table pointer is expected in %rdi (first parameter)
 *
 */
	.globl	sev_verify_cbit
	.balign	{FUNC_ALIGN}, 0x90
sev_verify_cbit:
	/* First check if a C-bit was detected */
	movq	sme_me_mask(%rip), %rsi
	testq	%rsi, %rsi
	jz	3f

	/* sme_me_mask != 0 could mean SME or SEV - Check also for SEV */
	movq	sev_status(%rip), %rsi
	testq	%rsi, %rsi
	jz	3f

	/* Save CR4 in %rsi */
	movq	%cr4, %rsi

	/* Disable Global Pages */
	movq	%rsi, %rdx
	andq	$(~{X86_CR4_PGE}), %rdx
	movq	%rdx, %cr4

	/*
	 * Verified that running under SEV - now get a random value using
	 * RDRAND. This instruction is mandatory when running as an SEV guest.
	 *
	 * Don't bail out of the loop if RDRAND returns errors. It is better to
	 * prevent forward progress than to work with a non-random value here.
	 */
1:	rdrand	%rdx
	jnc	1b

	/* Store value to memory and keep it in %rdx */
	movq	%rdx, sev_check_data(%rip)

	/* Backup current %cr3 value to restore it later */
	movq	%cr3, %rcx

	/* Switch to new %cr3 - This might unmap the stack */
	movq	%rdi, %cr3

	/*
	 * Compare value in %rdx with memory location. If C-bit is incorrect
	 * this would read the encrypted data and make the check fail.
	 */
	cmpq	%rdx, sev_check_data(%rip)

	/* Restore old %cr3 */
	movq	%rcx, %cr3

	/* Restore previous CR4 */
	movq	%rsi, %cr4

	/* Check CMPQ result */
	je	3f

	/*
	 * The check failed, prevent any forward progress to prevent ROP
	 * attacks, invalidate the stack and go into a hlt loop.
	 */
	xorl	%esp, %esp
	subq	$0x1000, %rsp
2:	hlt
	jmp 2b
3:
	/* Return page-table pointer */
	movq	%rdi, %rax
	RET
	.type	sev_verify_cbit, STT_FUNC
	.size	sev_verify_cbit, .-sev_verify_cbit


	.data

	.balign	8
	.globl	sme_me_mask
sme_me_mask:
	.quad 0
	.type	sme_me_mask, STT_OBJECT
	.size	sme_me_mask, .-sme_me_mask
	.globl	sev_status
sev_status:
	.quad 0
	.type	sev_status, STT_OBJECT
	.size	sev_status, .-sev_status
	.globl	sev_check_data
sev_check_data:
	.quad 0
	.type	sev_check_data, STT_OBJECT
	.size	sev_check_data, .-sev_check_data

boot32_idt:
	.rept	32
	.quad	0
	.endr
	.type	boot32_idt, STT_OBJECT
	.size	boot32_idt, .-boot32_idt

boot32_idt_desc:
	.word	. - boot32_idt - 1
	.long	0
	.type	boot32_idt_desc, STT_OBJECT
	.size	boot32_idt_desc, .-boot32_idt_desc
"##,
    MSR_AMD64_SEV_ES_GHCB = const MSR_AMD64_SEV_ES_GHCB,
    MSR_AMD64_SEV = const MSR_AMD64_SEV,
    MSR_AMD64_SEV_ENABLED_BIT = const MSR_AMD64_SEV_ENABLED_BIT,
    X86_CR0_PE = const X86_CR0_PE,
    X86_CR0_PG = const X86_CR0_PG,
    X86_CR4_PGE = const X86_CR4_PGE,
    X86_TRAP_VC = const X86_TRAP_VC,
    __KERNEL32_CS = const __KERNEL32_CS,
    FUNC_ALIGN = const FUNC_ALIGN,
    CONFIG_MITIGATION_SLS = const CONFIG_MITIGATION_SLS,
    options(att_syntax)
);
