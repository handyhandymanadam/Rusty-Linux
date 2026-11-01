/* Userspace stand-ins for what the extracted part of port/pristine/arch/x86/kernel/idt.c needs. The structure layouts and the two
 * header inlines (init_idt_data, idt_init_desc, native_write_idt_entry) are the kernel's own text (desc_defs.h / desc.h), so the
 * compiler lays out the bitfields; load_idt() records what would be loaded; set_bit() is the plain operation. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define __init
#define __initconst
#define __page_aligned_bss __attribute__((aligned(4096)))
#define __ro_after_init
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define BUG_ON(x) do { if (x) { g_bug++; } } while (0)
unsigned g_bug;
#define IDT_ENTRIES 256
#define NR_VECTORS 256
#define NUM_EXCEPTION_VECTORS 32
#define __KERNEL_CS 0x10
#define X86_TRAP_DB 1
#define X86_TRAP_BP 3
#define X86_TRAP_PF 14
#define X86_TRAP_VE 20
#ifdef CONFIG_X86_KERNEL_IBT
#define EARLY_IDT_HANDLER_SIZE 13
#else
#define EARLY_IDT_HANDLER_SIZE 9
#endif
#define CONFIG_X86_64 1
enum desc_type { GATE_INTERRUPT = 0xE };
struct idt_bits { u16 ist : 3, zero : 5, type : 5, dpl : 2, p : 1; } __attribute__((packed));
struct idt_data { unsigned int vector; unsigned int segment; struct idt_bits bits; const void *addr; };
struct gate_struct { u16 offset_low; u16 segment; struct idt_bits bits; u16 offset_middle; u32 offset_high; u32 reserved; } __attribute__((packed));
typedef struct gate_struct gate_desc;
struct desc_ptr { unsigned short size; unsigned long address; } __attribute__((packed));
_Static_assert(sizeof(struct idt_data) == 24 && offsetof(struct idt_data, bits) == 8 && offsetof(struct idt_data, addr) == 16, "idt_data");
_Static_assert(sizeof(gate_desc) == 16 && sizeof(struct desc_ptr) == 10, "gate");
extern unsigned long system_vectors[];
void asm_exc_debug(void); void asm_exc_int3(void); void asm_exc_page_fault(void); void asm_exc_virtualization_exception(void);
extern const char early_idt_handler_array[NUM_EXCEPTION_VECTORS][EARLY_IDT_HANDLER_SIZE];
/* recorded by load_idt: every call, in order */
struct lidt_rec { unsigned short size; unsigned long address; };
extern struct lidt_rec g_lidt[16]; extern unsigned g_nlidt;
static inline void load_idt(const struct desc_ptr *d) { if (g_nlidt < 16) { g_lidt[g_nlidt].size = d->size; g_lidt[g_nlidt].address = d->address; } g_nlidt++; }
static inline void set_bit(long nr, unsigned long *addr) { addr[nr / 64] |= 1UL << (nr % 64); }
#define write_idt_entry(dt, entry, g) native_write_idt_entry(dt, entry, g)
static inline void native_write_idt_entry(gate_desc *idt, int entry, const gate_desc *gate) { memcpy(&idt[entry], gate, sizeof(*gate)); }
static inline void init_idt_data(struct idt_data *data, unsigned int n, const void *addr)
{
	BUG_ON(n > 0xFF);
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
