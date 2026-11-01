// SPDX-License-Identifier: GPL-2.0-or-later
//! Rust replacement for arch/x86/boot/bioscall.S (RMASM, Phase C2): `intcall`, the real-mode setup's "glove box"
//! for BIOS calls (`void intcall(u8 int_no, const struct biosregs *ireg, struct biosregs *oreg)`; regparm=3: int_no in
//! %al, ireg in %edx, oreg in %ecx), as 16-bit (`.code16`) `global_asm!` in section `.inittext`. The text is the .S verbatim
//! (AT&T). It has no cpp macros and no header constants; the `.type`/`.size` lines are already explicit in the .S.
//! The object is the contract: rig/rmasm/check.sh (sections, `llvm-objdump -D -r -M i8086`, symbols, relocations, bytes);
//! setup.elf and bzImage byte-identical with `boot_rmasm_rust=`.
//! TEST-GAP: the self-modifying `INT` byte (label 3) is patched at run time in `.inittext`, which is in the setup image
//! (RAM at boot), so it works under QEMU; on a loader that puts setup in ROM it could not: unchanged from the C
//! kernel. Only a legacy-BIOS boot executes it (EFI/OVMF skips the real-mode setup). The 'oreg == NULL' skip (label 4) is never
//! taken by the current callers except where the setup passes NULL (e.g. the video code); QEMU/SeaBIOS only, no real BIOS.
// C-HEADERS:

use core::arch::global_asm;

global_asm!(
    r#"
/*
 * "Glove box" for BIOS calls.  Avoids the constant problems with BIOSes
 * touching registers they shouldn't be.
 */

	.code16
	.section ".inittext","ax"
	.globl	intcall
	.type	intcall, @function
intcall:
	/* Self-modify the INT instruction.  Ugly, but works. */
	cmpb	%al, 3f
	je	1f
	movb	%al, 3f
	jmp	1f		/* Synchronize pipeline */
1:
	/* Save state */
	pushfl
	pushw	%fs
	pushw	%gs
	pushal

	/* Copy input state to stack frame */
	subw	$44, %sp
	movw	%dx, %si
	movw	%sp, %di
	movw	$11, %cx
	rep movsl

	/* Pop full state from the stack */
	popal
	popw	%gs
	popw	%fs
	popw	%es
	popw	%ds
	popfl

	/* Actual INT */
	.byte	0xcd		/* INT opcode */
3:	.byte	0

	/* Push full state to the stack */
	pushfl
	pushw	%ds
	pushw	%es
	pushw	%fs
	pushw	%gs
	pushal

	/* Re-establish C environment invariants */
	cld
	movzwl	%sp, %esp
	movw	%cs, %ax
	movw	%ax, %ds
	movw	%ax, %es

	/* Copy output state from stack frame */
	movw	68(%esp), %di	/* Original %cx == 3rd argument */
	andw	%di, %di
	jz	4f
	movw	%sp, %si
	movw	$11, %cx
	rep movsl
4:	addw	$44, %sp

	/* Restore state and return */
	popal
	popw	%gs
	popw	%fs
	popfl
	retl
	.size	intcall, .-intcall
"#,
    options(att_syntax)
);
