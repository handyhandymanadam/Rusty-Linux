// SPDX-License-Identifier: GPL-2.0
/*
 * misc_cfg.c
 *
 * Build- and config-dependent facts that misc_rs.rs (the Rust replacement of
 * parts of misc.c) reads. Rust cannot see the preprocessor, so each fact is an
 * exported const computed here with the same #include set misc.c has. No logic
 * lives here.
 */

#include "misc.h"
#include "../voffset.h"

const unsigned long misc_load_physical_addr = LOAD_PHYSICAL_ADDR;
const unsigned long misc_start_kernel_map = __START_KERNEL_map;
/* handle_relocations(): max_addr = min_addr + (VO___bss_start - VO__text) */
const unsigned long misc_text_to_bss_start = VO___bss_start - VO__text;

/* extract_kernel() (misc_rs.rs): the malloc heap size, the kernel alignment and the mapping-area limit */
const unsigned long misc_boot_heap_size = BOOT_HEAP_SIZE;
const unsigned long misc_min_kernel_align = MIN_KERNEL_ALIGN;
const unsigned long misc_kernel_image_size = KERNEL_IMAGE_SIZE;
