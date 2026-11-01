/* Host stand-in for boot.h/io.h as used by arch/x86/boot/pm.c. The GDT macros come from the REAL kernel headers
 * (asm/segment.h, asm/desc_defs.h: only their #define lines, extracted mechanically by run-pm-diff.sh into asm/). */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct setup_header {   /* uapi/asm/bootparam.h layout up to code32_start (packed, hdr at 0x1f1) */
	u8 setup_sects; u16 root_flags; u32 syssize; u16 ram_size; u16 vid_mode; u16 root_dev; u16 boot_flag;
	u16 jump; u32 header; u16 version; u32 realmode_swtch; u16 start_sys_seg; u16 kernel_version;
	u8 type_of_loader; u8 loadflags; u16 setup_move_size; u32 code32_start;
} __attribute__((packed));
struct boot_params { u8 _pad[0x1f1]; struct setup_header hdr; u8 _pad2[4096 - 0x1f1 - sizeof(struct setup_header)]; } __attribute__((packed));
_Static_assert(offsetof(struct boot_params, hdr.realmode_swtch) == 0x208, "realmode_swtch");
_Static_assert(offsetof(struct boot_params, hdr.code32_start) == 0x214, "code32_start");
_Static_assert(sizeof(struct boot_params) == 4096, "boot_params");
extern struct boot_params boot_params;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
extern struct port_io_ops pio_ops;
#define inb  pio_ops.f_inb
#define outb pio_ops.f_outb
static inline void io_delay(void) { const u16 DELAY_PORT = 0x80; outb(0, DELAY_PORT); }
u16 mock_ds(void);
static inline u16 ds(void) { return mock_ds(); }
#ifndef PM_DIFF_HARNESS
int enable_a20(void); void puts(const char *s); void __attribute__((noreturn)) die(void);
void __attribute__((noreturn)) protected_mode_jump(u32 entrypoint, u32 bootparams);
#endif
