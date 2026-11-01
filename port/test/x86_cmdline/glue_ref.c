/* The port/tree glue arch/x86/lib/cmdline.c (what the kernel builds under CONFIG_RUST), entries renamed r_*. */
#define cmdline_find_option_bool r_cmdline_find_option_bool
#define cmdline_find_option r_cmdline_find_option
#include CMDLINE_GLUE_C
