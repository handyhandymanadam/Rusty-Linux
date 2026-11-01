/* SPDX-License-Identifier: GPL-2.0 */
/* Shim for arch/x86/include/asm/misc.h. run.sh checks the declaration below
 * against the kernel header, so this cannot drift into a different program. */
#ifndef _ASM_X86_MISC_H
#define _ASM_X86_MISC_H
int num_digits(int val);
#endif
