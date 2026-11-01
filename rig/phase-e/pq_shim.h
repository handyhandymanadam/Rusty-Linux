/* Userspace stand-ins for what port/pristine/arch/x86/kernel/platform-quirks.c needs. The struct layouts are
 * asserted against the numbers platform_quirks_rs.rs uses; the same numbers are checked against the kernel's
 * own headers by layout-check.c (in-tree), so a wrong shim shows as a failed assert or a C != Rust mismatch. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define __init
#define X86_SUBARCH_PC 0
#define X86_SUBARCH_LGUEST 1
#define X86_SUBARCH_XEN 2
#define X86_SUBARCH_INTEL_MID 3
#define X86_SUBARCH_CE4100 4
enum x86_legacy_i8042_state { X86_LEGACY_I8042_PLATFORM_ABSENT, X86_LEGACY_I8042_FIRMWARE_ABSENT, X86_LEGACY_I8042_EXPECTED_PRESENT };
struct x86_legacy_devices { int pnpbios; };
struct x86_legacy_features {
	enum x86_legacy_i8042_state i8042; int rtc; int warm_reset; int no_vga; int reserve_bios_regions;
	struct x86_legacy_devices devices;
};
struct x86_platform_ops {
	unsigned long (*calibrate_cpu)(void); unsigned long (*calibrate_tsc)(void); void (*get_wallclock)(void *);
	int (*set_wallclock)(const void *); void (*iommu_shutdown)(void); bool (*is_untracked_pat_range)(uint64_t, uint64_t);
	void (*nmi_init)(void); unsigned char (*get_nmi_reason)(void); void (*save_sched_clock_state)(void);
	void (*restore_sched_clock_state)(void); void (*apic_post_init)(void);
	struct x86_legacy_features legacy;
	void (*set_legacy_features)(void);
	void (*realmode_reserve)(void); void (*realmode_init)(void);
	void *hyper[4]; void *guest[8];
};
_Static_assert(offsetof(struct x86_platform_ops, legacy) == 88, "legacy");
_Static_assert(offsetof(struct x86_platform_ops, set_legacy_features) == 112, "set_legacy_features");
_Static_assert(offsetof(struct x86_legacy_features, i8042) == 0 && offsetof(struct x86_legacy_features, rtc) == 4 &&
	offsetof(struct x86_legacy_features, warm_reset) == 8 && offsetof(struct x86_legacy_features, reserve_bios_regions) == 16 &&
	offsetof(struct x86_legacy_features, devices.pnpbios) == 20, "legacy features");
struct __attribute__((packed)) setup_header_pq { char pad[0x23c - 0x1f1]; uint32_t hardware_subarch; };
struct __attribute__((packed)) boot_params_pq { char pad[0x1f1]; struct setup_header_pq hdr; };
extern struct boot_params_pq boot_params;
extern struct x86_platform_ops x86_platform;
#ifdef CONFIG_PNPBIOS_T
#define CONFIG_PNPBIOS 1
#endif
