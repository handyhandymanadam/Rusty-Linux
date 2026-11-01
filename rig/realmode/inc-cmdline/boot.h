/* Host stand-in for boot.h as used by arch/x86/boot/cmdline.c: the fs: segment register and the byte read through it are
 * routed to the memory model in cmdline-diff.c (a flat buffer indexed by seg*16+offset). */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef unsigned int addr_t;
#define fallthrough __attribute__((__fallthrough__))
void mock_set_fs(u16);
u8 mock_rdfs8(u32);
static inline void set_fs(u16 s) { mock_set_fs(s); }
static inline u8 rdfs8(addr_t a) { return mock_rdfs8(a); }
