/* Reference for pgtable_64_rs.rs: the kernel's own C (extracted verbatim by gen-pgt-ref.sh). */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <linux/types.h>
#include <asm/bootparam.h>
typedef unsigned long phys_addr_t;
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define sizeof_field(T, m) sizeof(((T *)0)->m)
#define round_down(x, y) ((x) & ~((__typeof__(x))((y)-1)))
#define PAGE_SIZE 4096UL
#define BIOS_START_MIN 0x20000U
#define BIOS_START_MAX 0x9f000U
#define TRAMPOLINE_32BIT_SIZE (2 * PAGE_SIZE)
#define EFI32_LOADER_SIGNATURE "EL32"
#define EFI64_LOADER_SIGNATURE "EL64"
enum { E820_TYPE_RAM = 1 };
/* the kernel's sanitize_boot_params uses these helpers: */
#define BUILD_BUG_ON_ZERO_MSG(...) 0
struct boot_params *boot_params_ptr;
static unsigned short g_ebda_word, g_bios_word;
#include "REFINC"

/* exported to the Rust comparison */
unsigned long c_place(int efi, unsigned short ebda, unsigned short bios, const struct boot_e820_entry *tab, int n)
{
	static struct boot_params bp;
	memset(&bp, 0, sizeof bp);
	memcpy(&bp.efi_info.efi_loader_signature, efi == 1 ? "EL32" : efi == 2 ? "EL64" : "XXXX", 4);
	bp.e820_entries = n;
	memcpy(bp.e820_table, tab, n * sizeof(*tab));
	g_ebda_word = ebda; g_bios_word = bios;
	boot_params_ptr = &bp;
	return find_trampoline_placement();
}
void c_sanitize(unsigned char *bp4096) { sanitize_boot_params((struct boot_params *)bp4096); }

/* dummies so the included pgtable_64_rs.rs links in userspace (never called there) */
int cmdline_find_option_bool(const char *o) { return 0; }
char trampoline_32bit_src[1]; unsigned short trampoline_ljmp_imm_offset;
