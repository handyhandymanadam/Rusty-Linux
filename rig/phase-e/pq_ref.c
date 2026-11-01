/* Reference for platform-quirks.c: the REAL C file (port/pristine), `#include` lines dropped, compiled against pq_shim.h. */
#include "pq_shim.h"
struct x86_platform_ops x86_platform;
struct boot_params_pq boot_params;
_Static_assert(offsetof(struct boot_params_pq, hdr.hardware_subarch) == 0x23c, "hardware_subarch");
unsigned g_cb_calls;
static void cb(void) { g_cb_calls++; x86_platform.legacy.rtc ^= 0x55; x86_platform.legacy.no_vga = 9 + x86_platform.legacy.warm_reset;
	x86_platform.legacy.devices.pnpbios += 3 * x86_platform.legacy.reserve_bios_regions + x86_platform.legacy.i8042; }
#include PQINC
void *xp_ptr(void) { return &x86_platform; }
size_t xp_size(void) { return sizeof x86_platform; }
void set_subarch(uint32_t v) { boot_params.hdr.hardware_subarch = v; }
void *cb_ptr(void) { return (void *)cb; }
unsigned cb_calls(void) { return g_cb_calls; }
void cb_reset(void) { g_cb_calls = 0; }
void c_quirks(void) { x86_early_init_platform_quirks(); }
int c_pnp_disabled(void) { return x86_pnpbios_disabled(); }
