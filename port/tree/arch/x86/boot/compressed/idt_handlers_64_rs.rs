// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/compressed/idt_handlers_64.S (STUBH, Phase C):
//! early IDT handler entry points (Joerg Roedel, SUSE).
//!
//! The assembly is the .S text verbatim in AT&T syntax. `SYM_FUNC_START(name)` / `SYM_FUNC_END(name)`
//! (include/linux/linkage.h, as the preprocessor expands them for this object) are written out:
//!     .globl name ; .balign CONFIG_FUNCTION_ALIGNMENT, 0x90 ; name:   ...   .type name, STT_FUNC ; .size name, .-name
//! `ORIG_RAX` (entry/calling.h) is a `const` operand. The two #VC handlers exist only with
//! `--cfg=amd_mem_encrypt` (= CONFIG_AMD_MEM_ENCRYPT), tested with `.if`. Each handler calls a C/Rust function
//! (do_boot_page_fault, do_boot_nmi_trap, do_vc_no_ghcb, do_boot_stage2_vc) by symbol.
//! TEST-GAP: boot_page_fault runs under rig/stubh/trial.sh -p pf (an unmapped read in extract_kernel(); with `addq $8,%rsp` ->
//! `$16` the boot dies). boot_nmi_trap (needs an NMI at the right moment) and boot_stage1_vc / boot_stage2_vc (#VC: an SEV-ES guest
//! is needed) never run in this rig. They are the same macro expansion as boot_page_fault and object-identical to the .S.
// C-HEADERS: asm/segment.h "../../entry/calling.h"

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

const ORIG_RAX: usize = 15 * 8; // C: ORIG_RAX

// #ifdef CONFIG_AMD_MEM_ENCRYPT: `--cfg=amd_mem_encrypt`, tested by the assembler's `.if` so the whole text is ONE
// global_asm! block (separate blocks are not guaranteed to be emitted in source order, and the macro must come first).
const CONFIG_AMD_MEM_ENCRYPT: usize = cfg!(amd_mem_encrypt) as usize; // nocheck

global_asm!(
    r#"
.macro EXCEPTION_HANDLER name function error_code=0
	.globl	\name
	.balign	{FUNC_ALIGN}, 0x90
\name:

	/* Build pt_regs */
	.if \error_code == 0
	pushq   $0
	.endif

	pushq   %rdi
	pushq   %rsi
	pushq   %rdx
	pushq   %rcx
	pushq   %rax
	pushq   %r8
	pushq   %r9
	pushq   %r10
	pushq   %r11
	pushq   %rbx
	pushq   %rbp
	pushq   %r12
	pushq   %r13
	pushq   %r14
	pushq   %r15

	/* Call handler with pt_regs */
	movq    %rsp, %rdi
	/* Error code is second parameter */
	movq	{ORIG_RAX}(%rsp), %rsi
	call    \function

	/* Restore regs */
	popq    %r15
	popq    %r14
	popq    %r13
	popq    %r12
	popq    %rbp
	popq    %rbx
	popq    %r11
	popq    %r10
	popq    %r9
	popq    %r8
	popq    %rax
	popq    %rcx
	popq    %rdx
	popq    %rsi
	popq    %rdi

	/* Remove error code and return */
	addq    $8, %rsp

	iretq
	.type	\name, STT_FUNC
	.size	\name, .-\name
	.endm

	.text
	.code64

EXCEPTION_HANDLER	boot_page_fault do_boot_page_fault error_code=1
EXCEPTION_HANDLER	boot_nmi_trap do_boot_nmi_trap error_code=0

	.if	{CONFIG_AMD_MEM_ENCRYPT}	/* #ifdef CONFIG_AMD_MEM_ENCRYPT */
EXCEPTION_HANDLER	boot_stage1_vc do_vc_no_ghcb		error_code=1
EXCEPTION_HANDLER	boot_stage2_vc do_boot_stage2_vc	error_code=1
	.endif
"#,
    ORIG_RAX = const ORIG_RAX,
    FUNC_ALIGN = const FUNC_ALIGN,
    CONFIG_AMD_MEM_ENCRYPT = const CONFIG_AMD_MEM_ENCRYPT,
    options(att_syntax)
);
