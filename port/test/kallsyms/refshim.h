/* Stand-ins for what the pristine slice of kernel/kallsyms.c uses. The kallsyms tables are pointers the test points at its own generated tables. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define KSYM_NAME_LEN 512
#define ESRCH 3
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
extern const int *kallsyms_offsets; extern const u8 *kallsyms_names; extern unsigned int kallsyms_num_syms; extern unsigned long kallsyms_relative_base;
extern const char *kallsyms_token_table; extern const u16 *kallsyms_token_index; extern const unsigned int *kallsyms_markers; extern const u8 *kallsyms_seqs_of_names;
extern int ks_all_g; extern unsigned long init_lo_g, init_hi_g;
#define _einittext ((char *)0x7fff0000UL)
#define _end ((char *)0x7fff1000UL)
#define _etext ((char *)0x7fff2000UL)
#define IS_ENABLED(x) (ks_all_g)
#define CONFIG_KALLSYMS_ALL 1
static inline bool is_kernel_inittext(unsigned long a) { return a >= init_lo_g && a < init_hi_g; }
#define static_assert(x) _Static_assert(1, "")
#endif
