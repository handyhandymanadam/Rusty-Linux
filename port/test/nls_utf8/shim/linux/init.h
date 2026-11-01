/* Shim: only the types and attributes include/linux/nls.h and nls_utf8.c need. */
#ifndef SHIM_INIT_H
#define SHIM_INIT_H
#include <stdint.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
/* the kernel typedefs u16 wchar_t; system headers must come first */
#define wchar_t knls_wchar_t
#define __init
#define __exit
struct module;
#endif
