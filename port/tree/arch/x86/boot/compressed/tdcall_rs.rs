// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/compressed/tdcall.S (STUBH, Phase C), which is
//! `#include "../../coco/tdx/tdcall.S"` and that in turn instantiates `TDX_MODULE_CALL`
//! (arch/x86/virt/vmx/tdx/tdxcall.S) three times: `__tdcall`, `__tdcall_ret`, `__tdcall_saved_ret`.
//! Only in the stub with CONFIG_INTEL_TDX_GUEST.
//!
//! The macro is carried with its `host=0` arm only: tdcall.S never instantiates `host=1`
//! (SEAMCALL is the TDX *host* instruction, used by the kernel proper), and the stub has no
//! exception-table section for its `_ASM_EXTABLE_FAULT`. `tdcall` is the cpp macro for
//! `.byte 0x66,0x0f,0x01,0xcc`. `FRAME_BEGIN`/`FRAME_END` (asm/frame.h) are `push %rbp ; mov %rsp,%rbp`
//! / `pop %rbp` with CONFIG_FRAME_POINTER (`--cfg=frame_pointer`), empty without. `RET` is `ret`,
//! or `ret; int3` with CONFIG_MITIGATION_SLS (`--cfg=mitigation_sls`). `TDX_MODULE_*` are the
//! offsets of `struct tdx_module_args` from asm-offsets.h. SYM_FUNC_START/END are written out.
//! Constants are checked against the headers by rig/stubh/consts_check.py.
//! TEST-GAP: ALL of it. `__tdcall*` run only inside an Intel TDX guest (TDCALL is #UD elsewhere); the CONFIG_INTEL_TDX_GUEST build
//! (build-tdx) boots and links these functions but never calls them. A sabotage here is caught by the object comparison only.
// C-HEADERS: asm/asm-offsets.h

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

const TDX_MODULE_RCX: usize = 0; // C: TDX_MODULE_rcx
const TDX_MODULE_RDX: usize = 8; // C: TDX_MODULE_rdx
const TDX_MODULE_R8: usize = 16; // C: TDX_MODULE_r8
const TDX_MODULE_R9: usize = 24; // C: TDX_MODULE_r9
const TDX_MODULE_R10: usize = 32; // C: TDX_MODULE_r10
const TDX_MODULE_R11: usize = 40; // C: TDX_MODULE_r11
const TDX_MODULE_R12: usize = 48; // C: TDX_MODULE_r12
const TDX_MODULE_R13: usize = 56; // C: TDX_MODULE_r13
const TDX_MODULE_R14: usize = 64; // C: TDX_MODULE_r14
const TDX_MODULE_R15: usize = 72; // C: TDX_MODULE_r15
const TDX_MODULE_RBX: usize = 80; // C: TDX_MODULE_rbx
const TDX_MODULE_RDI: usize = 88; // C: TDX_MODULE_rdi
const TDX_MODULE_RSI: usize = 96; // C: TDX_MODULE_rsi

// Kconfig switches the assembler text tests with `.if` (set from the stub's `--cfg` flags): everything below is ONE
// global_asm! block (separate blocks are not guaranteed to be emitted in source order, and a macro must precede its use).
const CONFIG_FRAME_POINTER: usize = cfg!(frame_pointer) as usize; // nocheck
const CONFIG_MITIGATION_SLS: usize = cfg!(mitigation_sls) as usize; // nocheck

global_asm!(
    r##"
	.macro	FRAME_BEGIN
	.if	{CONFIG_FRAME_POINTER}
	push	%rbp
	mov	%rsp, %rbp
	.endif
	.endm
	.macro	FRAME_END
	.if	{CONFIG_FRAME_POINTER}
	pop	%rbp
	.endif
	.endm

	.macro	RET
	ret
	.if	{CONFIG_MITIGATION_SLS}
	int3
	.endif
	.endm

.macro TDX_MODULE_CALL ret=0 saved=0
	FRAME_BEGIN

	/* Move Leaf ID to RAX */
	mov %rdi, %rax

	/* Move other input regs from 'struct tdx_module_args' */
	movq	{TDX_MODULE_RCX}(%rsi), %rcx
	movq	{TDX_MODULE_RDX}(%rsi), %rdx
	movq	{TDX_MODULE_R8}(%rsi),  %r8
	movq	{TDX_MODULE_R9}(%rsi),  %r9
	movq	{TDX_MODULE_R10}(%rsi), %r10
	movq	{TDX_MODULE_R11}(%rsi), %r11

.if \saved
	/*
	 * Move additional input regs from the structure.  For simplicity
	 * assume that anything needs the callee-saved regs also tramples
	 * on RDI/RSI (see VP.ENTER).
	 */
	/* Save those callee-saved GPRs as mandated by the x86_64 ABI */
	pushq	%rbx
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	movq	{TDX_MODULE_R12}(%rsi), %r12
	movq	{TDX_MODULE_R13}(%rsi), %r13
	movq	{TDX_MODULE_R14}(%rsi), %r14
	movq	{TDX_MODULE_R15}(%rsi), %r15
	movq	{TDX_MODULE_RBX}(%rsi), %rbx

.if \ret
	/* Save the structure pointer as RSI is about to be clobbered */
	pushq	%rsi
.endif

	movq	{TDX_MODULE_RDI}(%rsi), %rdi
	/* RSI needs to be done at last */
	movq	{TDX_MODULE_RSI}(%rsi), %rsi
.endif	/* \saved */

	.byte 0x66,0x0f,0x01,0xcc	/* tdcall */

.if \ret
.if \saved
	/*
	 * Restore the structure from stack to save the output registers
	 *
	 * In case of VP.ENTER returns due to TDVMCALL, all registers are
	 * valid thus no register can be used as spare to restore the
	 * structure from the stack (see "TDH.VP.ENTER Output Operands
	 * Definition on TDCALL(TDG.VP.VMCALL) Following a TD Entry").
	 * For this case, need to make one register as spare by saving it
	 * to the stack and then manually load the structure pointer to
	 * the spare register.
	 *
	 * Note for other TDCALLs/SEAMCALLs there are spare registers
	 * thus no need for such hack but just use this for all.
	 */
	pushq	%rax		/* save the TDCALL/SEAMCALL return code */
	movq	8(%rsp), %rax	/* restore the structure pointer */
	movq	%rsi, {TDX_MODULE_RSI}(%rax)	/* save RSI */
	popq	%rax		/* restore the return code */
	popq	%rsi		/* pop the structure pointer */

	/* Copy additional output regs to the structure  */
	movq %r12, {TDX_MODULE_R12}(%rsi)
	movq %r13, {TDX_MODULE_R13}(%rsi)
	movq %r14, {TDX_MODULE_R14}(%rsi)
	movq %r15, {TDX_MODULE_R15}(%rsi)
	movq %rbx, {TDX_MODULE_RBX}(%rsi)
	movq %rdi, {TDX_MODULE_RDI}(%rsi)
.endif	/* \saved */

	/* Copy output registers to the structure */
	movq %rcx, {TDX_MODULE_RCX}(%rsi)
	movq %rdx, {TDX_MODULE_RDX}(%rsi)
	movq %r8,  {TDX_MODULE_R8}(%rsi)
	movq %r9,  {TDX_MODULE_R9}(%rsi)
	movq %r10, {TDX_MODULE_R10}(%rsi)
	movq %r11, {TDX_MODULE_R11}(%rsi)
.endif	/* \ret */

.if \saved && \ret
	/*
	 * Clear registers shared by guest for VP.VMCALL/VP.ENTER to prevent
	 * speculative use of guest's/VMM's values, including those are
	 * restored from the stack.
	 *
	 * See arch/x86/kvm/vmx/vmenter.S:
	 *
	 * In theory, a L1 cache miss when restoring register from stack
	 * could lead to speculative execution with guest's values.
	 *
	 * Note: RBP/RSP are not used as shared register.  RSI has been
	 * restored already.
	 *
	 * XOR is cheap, thus unconditionally do for all leafs.
	 */
	xorl %ecx,  %ecx
	xorl %edx,  %edx
	xorl %r8d,  %r8d
	xorl %r9d,  %r9d
	xorl %r10d, %r10d
	xorl %r11d, %r11d
	xorl %r12d, %r12d
	xorl %r13d, %r13d
	xorl %r14d, %r14d
	xorl %r15d, %r15d
	xorl %ebx,  %ebx
	xorl %edi,  %edi
.endif	/* \ret && \host */

.if \saved
	/* Restore callee-saved GPRs as mandated by the x86_64 ABI */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbx
.endif	/* \saved */

	FRAME_END
	RET
.endm

.section .noinstr.text, "ax"

/*
 * __tdcall()  - Used by TDX guests to request services from the TDX
 * module (does not include VMM services) using TDCALL instruction.
 *
 * @fn   (RDI)	- TDCALL Leaf ID, moved to RAX
 * @args (RSI)	- struct tdx_module_args for input
 *
 * Only RCX/RDX/R8-R11 are used as input registers.
 *
 * Return status of TDCALL via RAX.
 */
	.globl	__tdcall
	.balign	{FUNC_ALIGN}, 0x90
__tdcall:
	TDX_MODULE_CALL
	.type	__tdcall, STT_FUNC
	.size	__tdcall, .-__tdcall

/*
 * __tdcall_ret() - TDCALL, with saving output registers to the
 * 'struct tdx_module_args' used as input.
 */
	.globl	__tdcall_ret
	.balign	{FUNC_ALIGN}, 0x90
__tdcall_ret:
	TDX_MODULE_CALL ret=1
	.type	__tdcall_ret, STT_FUNC
	.size	__tdcall_ret, .-__tdcall_ret

/*
 * __tdcall_saved_ret() - TDCALL (including VMM services), with saving
 * output registers to the 'struct tdx_module_args' used as input/output.
 * All registers in @args are used as input/output registers.
 *
 * On successful completion, return the hypercall error code.
 */
	.globl	__tdcall_saved_ret
	.balign	{FUNC_ALIGN}, 0x90
__tdcall_saved_ret:
	TDX_MODULE_CALL ret=1 saved=1
	.type	__tdcall_saved_ret, STT_FUNC
	.size	__tdcall_saved_ret, .-__tdcall_saved_ret
"##,
    TDX_MODULE_RCX = const TDX_MODULE_RCX,
    TDX_MODULE_RDX = const TDX_MODULE_RDX,
    TDX_MODULE_R8 = const TDX_MODULE_R8,
    TDX_MODULE_R9 = const TDX_MODULE_R9,
    TDX_MODULE_R10 = const TDX_MODULE_R10,
    TDX_MODULE_R11 = const TDX_MODULE_R11,
    TDX_MODULE_R12 = const TDX_MODULE_R12,
    TDX_MODULE_R13 = const TDX_MODULE_R13,
    TDX_MODULE_R14 = const TDX_MODULE_R14,
    TDX_MODULE_R15 = const TDX_MODULE_R15,
    TDX_MODULE_RBX = const TDX_MODULE_RBX,
    TDX_MODULE_RDI = const TDX_MODULE_RDI,
    TDX_MODULE_RSI = const TDX_MODULE_RSI,
    FUNC_ALIGN = const FUNC_ALIGN,
    CONFIG_FRAME_POINTER = const CONFIG_FRAME_POINTER,
    CONFIG_MITIGATION_SLS = const CONFIG_MITIGATION_SLS,
    options(att_syntax)
);
