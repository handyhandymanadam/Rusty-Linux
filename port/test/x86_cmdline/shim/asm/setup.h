#ifndef SHIM_SETUP_H
#define SHIM_SETUP_H
#include <linux/types.h>
#define COMMAND_LINE_SIZE 2048		/* arch/x86/include/uapi/asm/setup.h */
#ifdef WITH_BOOL
extern bool builtin_cmdline_added;
#else
#define builtin_cmdline_added 0		/* include/asm/setup.h, !CONFIG_CMDLINE_BOOL */
#endif
#endif
