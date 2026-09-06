#pragma once
#include <stdio.h>
#define KERN_ERR ""
/* bad_io_access()'s WARN(1, ...) -- never exercised by this differential
 * (every scenario uses a valid PIO or MMIO cookie; see drv.c's header
 * comment), but still needs to compile.
 */
#define WARN(cond, fmt, ...) \
	({ bool __ret = !!(cond); if (__ret) fprintf(stderr, "%s", fmt); (void)0; __ret; })
