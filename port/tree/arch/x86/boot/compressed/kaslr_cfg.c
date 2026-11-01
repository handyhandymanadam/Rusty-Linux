// SPDX-License-Identifier: GPL-2.0
/*
 * kaslr_cfg.c
 *
 * Build- and config-dependent facts that kaslr_rs.rs (the Rust replacement of
 * kaslr.c, including arch/x86/lib/kaslr.c, lib/ctype.c and lib/cmdline.c)
 * reads. Rust cannot see the preprocessor, so each fact is an exported object
 * (or, for the one RUNTIME value, a function) computed here with the same
 * #include set and #defines kaslr.c has at its top. No logic lives here.
 */

/*
 * isspace() in linux/ctype.h is expected by next_args() to filter
 * out "space/lf/tab". While boot/ctype.h conflicts with linux/ctype.h,
 * since isdigit() is implemented in both of them. Hence disable it
 * here.
 */
#define BOOT_CTYPE_H

#include "misc.h"
#include "error.h"
#include "../string.h"
#include "efi.h"

#include <generated/compile.h>
#include <generated/utsversion.h>
#include <generated/utsrelease.h>

#define _SETUP
#include <asm/setup.h>	/* For COMMAND_LINE_SIZE */
#undef _SETUP

/* Simplified build-specific string for starting entropy (identical to kaslr.c's build_str). */
const char kaslr_build_str[] = UTS_RELEASE " (" LINUX_COMPILE_BY "@"
		LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION;
const unsigned long kaslr_build_str_size = sizeof(kaslr_build_str);

const unsigned long kaslr_physical_align = CONFIG_PHYSICAL_ALIGN;
const unsigned long kaslr_load_physical_addr = LOAD_PHYSICAL_ADDR;
const unsigned long kaslr_kernel_image_size = KERNEL_IMAGE_SIZE;
const unsigned long kaslr_command_line_size = COMMAND_LINE_SIZE;

/* MAXMEM is a runtime value with 5-level paging (pgtable_l5_enabled()). */
unsigned long kaslr_maxmem(void)
{
	return MAXMEM;
}

#ifdef CONFIG_EFI
/* efi_soft_reserve_enabled() is IS_ENABLED(CONFIG_EFI_SOFT_RESERVE) && __efi_soft_reserve_enabled(). */
bool kaslr_soft_reserve_enabled(void)
{
	return efi_soft_reserve_enabled();
}
#endif
