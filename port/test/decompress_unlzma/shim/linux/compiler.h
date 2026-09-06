/* Userspace shim: decompress_unlzma.c includes this but uses nothing from
 * it directly (no likely()/unlikely()/READ_ONCE/etc appear in the file) --
 * except uint8_t/uint16_t/uint32_t/uint64_t, which the real kernel header
 * chain provides transitively (via <linux/types.h>) and this file never
 * includes on its own. */
#ifndef _SHIM_LINUX_COMPILER_H
#define _SHIM_LINUX_COMPILER_H
#include <stdint.h>
#endif
