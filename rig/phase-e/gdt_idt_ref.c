/* Reference for arch/x86/boot/startup/gdt_idt.c (6.18.49): the #VC gate built by
 * init_idt_data() + idt_init_desc() + native_write_idt_entry() for vector X86_TRAP_VC.
 * The struct definitions are copied verbatim from arch/x86/include/asm/desc_defs.h, desc.h;
 * their layout and the constants are checked against the kernel's own compile by
 * rig/phase-e/layout-check.c. Same method as rig/stube-parity/idt_ref.c. */
#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define __KERNEL_CS 0x10
enum { GATE_INTERRUPT = 0xE };
struct idt_bits { u16 ist : 3, zero : 5, type : 5, dpl : 2, p : 1; } __attribute__((packed));
struct gate_struct {
	u16 offset_low; u16 segment; struct idt_bits bits; u16 offset_middle; u32 offset_high; u32 reserved;
} __attribute__((packed));
typedef struct gate_struct gate_desc;
struct idt_data { unsigned int vector; unsigned int segment; struct idt_bits bits; const void *addr; };

static inline void init_idt_data(struct idt_data *data, unsigned int n, const void *addr)
{
	memset(data, 0, sizeof(*data));
	data->vector	= n;
	data->addr	= addr;
	data->segment	= __KERNEL_CS;
	data->bits.type	= GATE_INTERRUPT;
	data->bits.p	= 1;
}
static inline void idt_init_desc(gate_desc *gate, const struct idt_data *d)
{
	unsigned long addr = (unsigned long) d->addr;
	gate->offset_low	= (u16) addr;
	gate->segment		= (u16) d->segment;
	gate->bits		= d->bits;
	gate->offset_middle	= (u16) (addr >> 16);
	gate->offset_high	= (u32) (addr >> 32);
	gate->reserved		= 0;
}
static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate)
{
	memcpy(&idt[entry], gate, sizeof(*gate));
}

/* startup_64_load_idt() with the table in a local array: returns entry 29 and whether any other
 * byte of the 32-entry table was touched. */
void c_vc_table(unsigned long handler, uint64_t out[2], int *others_zero)
{
	gate_desc table[32];
	struct idt_data data; gate_desc idt_desc;
	memset(table, 0, sizeof(table));
	init_idt_data(&data, 29, (void *)handler);
	idt_init_desc(&idt_desc, &data);
	native_write_idt_entry(table, 29, &idt_desc);
	memcpy(out, &table[29], 16);
	{ unsigned char z[16 * 32]; int ok = 1; memcpy(z, table, sizeof z);
	  for (int i = 0; i < 16 * 32; i++) if (!(i >= 29 * 16 && i < 30 * 16) && z[i]) ok = 0;
	  *others_zero = ok; }
}

/* symbols the included Rust object references (never executed in userspace) */
uint64_t gdt_page[16]; void vc_no_ghcb(void) {}
