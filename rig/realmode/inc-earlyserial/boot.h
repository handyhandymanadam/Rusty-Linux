/* Host stand-in for boot.h/io.h as used by arch/x86/boot/early_serial_console.c (rig/realmode/earlyserial-diff.c):
 * port I/O through pio_ops exactly like io.h, cmdline_find_option() is the harness's mock (boot.h's inline reads
 * boot_params.hdr.cmd_line_ptr and calls __cmdline_find_option; both are separately covered). */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
extern struct port_io_ops pio_ops;
#define inb  pio_ops.f_inb
#define outb pio_ops.f_outb
extern int early_serial_base;
void console_init(void);
int mock_cmdline_find_option(const char *option, char *buffer, int bufsize);
#define cmdline_find_option mock_cmdline_find_option
int strncmp(const char *cs, const char *ct, size_t count);
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base);
