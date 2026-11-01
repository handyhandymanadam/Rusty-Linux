/* Reference: the C of arch/x86/boot/compressed/idt_64.c set_idt_entry(), with the kernel's own
 * struct definitions copied verbatim from arch/x86/include/asm/desc_defs.h (6.18.49).
 * The layout of these copies is checked against the kernel's headers by layout-check.c (in-tree compile). */
#include <stdint.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32;
#define __KERNEL_CS 0x10
enum { GATE_TRAP = 0xF };
struct idt_bits { u16 ist : 3, zero : 5, type : 5, dpl : 2, p : 1; } __attribute__((packed));
struct gate_struct {
	u16 offset_low; u16 segment; struct idt_bits bits; u16 offset_middle; u32 offset_high; u32 reserved;
} __attribute__((packed));
typedef struct gate_struct gate_desc;

void c_gate(unsigned long address, uint64_t out[2])
{
	gate_desc entry;
	memset(&entry, 0, sizeof(entry));
	entry.offset_low    = (u16)(address & 0xffff);
	entry.segment       = __KERNEL_CS;
	entry.bits.type     = GATE_TRAP;
	entry.bits.p        = 1;
	entry.offset_middle = (u16)((address >> 16) & 0xffff);
	entry.offset_high   = (u32)(address >> 32);
	memcpy(out, &entry, sizeof(entry));
}

/* dummies so the included idt_64_rs.rs links in userspace (never called there) */
uint64_t boot_idt[64]; struct { u16 s; unsigned long a; } __attribute__((packed)) boot_idt_desc;
void boot_page_fault(void) {} void boot_nmi_trap(void) {}
