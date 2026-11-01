// SPDX-License-Identifier: GPL-2.0
//! Rust replacement for arch/x86/boot/startup/la57toggle.S (STUBH, Phase C): the 32-bit trampoline
//! (`trampoline_32bit_src`) the 64-bit stub copies into low memory to toggle CR4.LA57 (5-level
//! paging), and `trampoline_ljmp_imm_offset`, the offset of the far jump's immediate that
//! pgtable_64.c patches after the copy. The code lives in `.rodata`: it is DATA to the stub.
//! pgtable_64_rs.rs copies `TRAMPOLINE_32BIT_CODE_SIZE` bytes from it and patches the `ljmp` target.
//!
//! The text is the .S verbatim (AT&T, `.code32` inside), SYM_CODE_START/END, SYM_DATA written out.
//! The `.org trampoline_32bit_src + TRAMPOLINE_32BIT_CODE_SIZE` size limit is kept: it fails the
//! assembly if the trampoline grows, and pads `.rodata` up to exactly that size otherwise.
//! Constants (segments, CR0/CR4/EFER bits, MSR_EFER, the size) are `const` operands checked against
//! the headers by rig/stubh/consts_check.py. The object is in arch/x86/boot/startup/lib.a for the C
//! build; the Rust object is linked directly (the archive member is then never pulled).
//! TEST-GAP: the 4- to 5-level direction runs (rig/stubh/la57boot.sh: TCG `-cpu max`; sabotage `btcl`->`btrl` kills that boot). The
//! 5- to 4-level direction (a loader that enters with CR4.LA57 set, e.g. kexec from a 5-level kernel) never runs; it is the same
//! `btcl` toggle with a different CR3 value prepared by pgtable_64_rs.rs. KVM on this host (Ryzen 5 2600) has no LA57.
// C-HEADERS: linux/linkage.h asm/segment.h asm/boot.h asm/msr.h asm/processor-flags.h

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

const __KERNEL32_CS: usize = 0x08; // C: __KERNEL32_CS
const __KERNEL_CS: usize = 0x10; // C: __KERNEL_CS
const X86_CR0_PG_BIT: usize = 31; // C: X86_CR0_PG_BIT
const X86_CR4_LA57_BIT: usize = 12; // C: X86_CR4_LA57_BIT
const MSR_EFER: usize = 0xc000_0080; // C: MSR_EFER
const _EFER_LME: usize = 8; // C: _EFER_LME
const TRAMPOLINE_32BIT_CODE_SIZE: usize = 0xA0; // C: TRAMPOLINE_32BIT_CODE_SIZE

global_asm!(
    r##"
/*
 * This is the 32-bit trampoline that will be copied over to low memory. It
 * will be called using the ordinary 64-bit calling convention from code
 * running in 64-bit mode.
 *
 * Return address is at the top of the stack (might be above 4G).
 * The first argument (EDI) contains the address of the temporary PGD level
 * page table in 32-bit addressable memory which will be programmed into
 * register CR3.
 */

	.section ".rodata", "a", @progbits
	.globl	trampoline_32bit_src
	.balign	{FUNC_ALIGN}, 0x90
trampoline_32bit_src:
	/*
	 * Preserve callee save 64-bit registers on the stack: this is
	 * necessary because the architecture does not guarantee that GPRs will
	 * retain their full 64-bit values across a 32-bit mode switch.
	 */
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbp
	pushq	%rbx

	/* Preserve top half of RSP in a legacy mode GPR to avoid truncation */
	movq	%rsp, %rbx
	shrq	$32, %rbx

	/* Switch to compatibility mode (CS.L = 0 CS.D = 1) via far return */
	pushq	${__KERNEL32_CS}
	leaq	0f(%rip), %rax
	pushq	%rax
	lretq

	/*
	 * The 32-bit code below will do a far jump back to long mode and end
	 * up here after reconfiguring the number of paging levels. First, the
	 * stack pointer needs to be restored to its full 64-bit value before
	 * the callee save register contents can be popped from the stack.
	 */
.Lret:
	shlq	$32, %rbx
	orq	%rbx, %rsp

	/* Restore the preserved 64-bit registers */
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	retq

	.code32
0:
	/* Disable paging */
	movl	%cr0, %eax
	btrl	${X86_CR0_PG_BIT}, %eax
	movl	%eax, %cr0

	/* Point CR3 to the trampoline's new top level page table */
	movl	%edi, %cr3

	/* Set EFER.LME=1 as a precaution in case hypervsior pulls the rug */
	movl	${MSR_EFER}, %ecx
	rdmsr
	btsl	${_EFER_LME}, %eax
	/* Avoid writing EFER if no change was made (for TDX guest) */
	jc	1f
	wrmsr
1:
	/* Toggle CR4.LA57 */
	movl	%cr4, %eax
	btcl	${X86_CR4_LA57_BIT}, %eax
	movl	%eax, %cr4

	/* Enable paging again. */
	movl	%cr0, %eax
	btsl	${X86_CR0_PG_BIT}, %eax
	movl	%eax, %cr0

	/*
	 * Return to the 64-bit calling code using LJMP rather than LRET, to
	 * avoid the need for a 32-bit addressable stack. The destination
	 * address will be adjusted after the template code is copied into a
	 * 32-bit addressable buffer.
	 */
.Ljmp:	ljmpl	${__KERNEL_CS}, $(.Lret - trampoline_32bit_src)
	.type	trampoline_32bit_src, STT_NOTYPE
	.size	trampoline_32bit_src, .-trampoline_32bit_src

/*
 * This symbol is placed right after trampoline_32bit_src() so its address can
 * be used to infer the size of the trampoline code.
 */
	.globl	trampoline_ljmp_imm_offset
trampoline_ljmp_imm_offset:
	.word	.Ljmp + 1 - trampoline_32bit_src
	.type	trampoline_ljmp_imm_offset, STT_OBJECT
	.size	trampoline_ljmp_imm_offset, .-trampoline_ljmp_imm_offset

	/*
         * The trampoline code has a size limit.
         * Make sure we fail to compile if the trampoline code grows
         * beyond TRAMPOLINE_32BIT_CODE_SIZE bytes.
	 */
	.org	trampoline_32bit_src + {TRAMPOLINE_32BIT_CODE_SIZE}
"##,
    __KERNEL32_CS = const __KERNEL32_CS,
    __KERNEL_CS = const __KERNEL_CS,
    X86_CR0_PG_BIT = const X86_CR0_PG_BIT,
    X86_CR4_LA57_BIT = const X86_CR4_LA57_BIT,
    MSR_EFER = const MSR_EFER,
    _EFER_LME = const _EFER_LME,
    TRAMPOLINE_32BIT_CODE_SIZE = const TRAMPOLINE_32BIT_CODE_SIZE,
    FUNC_ALIGN = const FUNC_ALIGN,
    options(att_syntax)
);
