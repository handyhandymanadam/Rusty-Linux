/* Host stand-in for boot.h/io.h as used by arch/x86/boot/a20.c: segment accesses and the
 * port/BIOS interface are routed to the device model in a20-diff.c. */
#include <stdint.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef unsigned long addr_t;
struct biosregs {
	union { struct { u32 edi, esi, ebp, _esp, ebx, edx, ecx, eax; u16 gs, fs, es, ds; u32 eflags; };
	        struct { u16 di,_d1, si,_d2, bp,_d3, _sp,_d4, bx,_d5, dx,_d6, cx,_d7, ax,_d8; }; };
};
struct port_io_ops { u8 (*f_inb)(u16 port); void (*f_outb)(u8 v, u16 port); void (*f_outw)(u16 v, u16 port); };
extern struct port_io_ops pio_ops;
#define inb  pio_ops.f_inb
#define outb pio_ops.f_outb
void initregs(struct biosregs *reg);
void intcall(u8 int_no, const struct biosregs *ireg, struct biosregs *oreg);
void mock_set_fs(u16); void mock_set_gs(u16);
u32 mock_rdfs32(u32); void mock_wrfs32(u32, u32); u32 mock_rdgs32(u32);
static inline void io_delay(void) { const u16 DELAY_PORT = 0x80; outb(0, DELAY_PORT); }
static inline void set_fs(u16 s) { mock_set_fs(s); }
static inline void set_gs(u16 s) { mock_set_gs(s); }
static inline u32 rdfs32(addr_t a) { return mock_rdfs32(a); }
static inline void wrfs32(u32 v, addr_t a) { mock_wrfs32(v, a); }
static inline u32 rdgs32(addr_t a) { return mock_rdgs32(a); }
