// SPDX-License-Identifier: GPL-2.0-only
//! Rust replacement for arch/x86/boot/copy.S (RMASM, Phase C2): the real-mode setup's `memcpy`, `memset`,
//! `copy_from_fs`, `copy_to_fs`, as 16-bit (`.code16`) `global_asm!`. The text is the .S verbatim (AT&T
//! syntax). Mechanical expansion only: `SYM_FUNC_START_NOALIGN(x)` (linkage.h) = `.globl x ; x:`, and
//! `SYM_FUNC_END(x)` = `.type x, STT_FUNC ; .size x, .-x`. There are no header constants in this file.
//! The object is the contract: rig/rmasm/check.sh compares it with the .S object (sections, `llvm-objdump -D -r`,
//! symbols, relocations, bytes); the linked setup.elf and the bzImage are byte-identical with `boot_rmasm_rust=`.
//! TEST-GAP: (1) the 16-bit `rep movsl`/`rep stosl` tails (`cx & 3` bytes) are exercised by whatever the setup
//! code copies (boot_params, the command line, the video mode table) but no test pins every length 0..3 and
//! every alignment; covered by object identity. (2) `copy_from_fs`/`copy_to_fs` are only called by the setup code
//! reading/writing through %fs (e.g. the ISO-style boot params copy and `cmdline`); only a legacy-BIOS boot runs them.
// C-HEADERS: linux/linkage.h

use core::arch::global_asm;

global_asm!(
    r#"
/*
 * Memory copy routines
 */

	.code16
	.text

	.globl memcpy
memcpy:
	pushw	%si
	pushw	%di
	movw	%ax, %di
	movw	%dx, %si
	pushw	%cx
	shrw	$2, %cx
	rep movsl
	popw	%cx
	andw	$3, %cx
	rep movsb
	popw	%di
	popw	%si
	retl
	.type memcpy, STT_FUNC
	.size memcpy, .-memcpy

	.globl memset
memset:
	pushw	%di
	movw	%ax, %di
	movzbl	%dl, %eax
	imull	$0x01010101,%eax
	pushw	%cx
	shrw	$2, %cx
	rep stosl
	popw	%cx
	andw	$3, %cx
	rep stosb
	popw	%di
	retl
	.type memset, STT_FUNC
	.size memset, .-memset

	.globl copy_from_fs
copy_from_fs:
	pushw	%ds
	pushw	%fs
	popw	%ds
	calll	memcpy
	popw	%ds
	retl
	.type copy_from_fs, STT_FUNC
	.size copy_from_fs, .-copy_from_fs

	.globl copy_to_fs
copy_to_fs:
	pushw	%es
	pushw	%fs
	popw	%es
	calll	memcpy
	popw	%es
	retl
	.type copy_to_fs, STT_FUNC
	.size copy_to_fs, .-copy_to_fs
"#,
    options(att_syntax)
);
