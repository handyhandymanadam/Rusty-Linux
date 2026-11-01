/* Host stand-in for boot.h as used by arch/x86/boot/cpu.c and cpucheck.c (see cpu-diff.c / run-cpu-diff.sh).
 * Everything the setup code gets from the BIOS/hardware is routed to the device model in cpu-diff.c:
 * printf/puts/putchar/sprintf, cmdline_find_option_bool, has_eflag (32-bit build only), get_cpuflags/cpu/cpu_vendor. */
#ifndef BOOT_H
#define BOOT_H
#include <linux/types.h>
#include "bitops.h"
#include "cpuflags.h"		/* the real one: struct cpu_features, cpu, cpu_vendor, get_cpuflags() */
int mock_printf(const char *fmt, ...);
int mock_sprintf(char *buf, const char *fmt, ...);
void mock_puts(const char *s);
void mock_putchar(int c);
int mock_cmdline_find_option_bool(const char *opt);
unsigned char mock_has_eflag(unsigned long mask);
#define printf mock_printf
#define sprintf mock_sprintf
#define puts mock_puts
#define putchar mock_putchar
#define cmdline_find_option_bool mock_cmdline_find_option_bool
#undef has_eflag
#define has_eflag(m) mock_has_eflag(m)
int check_cpu(int *cpu_level_ptr, int *req_level_ptr, u32 **err_flags_ptr);
int check_knl_erratum(void);
int validate_cpu(void);
#endif
