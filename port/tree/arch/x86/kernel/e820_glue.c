// SPDX-License-Identifier: GPL-2.0-only
/*
 * Low level x86 E820 memory map handling functions.
 *
 * The firmware and bootloader passes us the "E820 table", which is the primary
 * physical memory layout description available about x86 systems.
 *
 * The kernel takes the E820 memory layout and optionally modifies it with
 * quirks and other tweaks, and feeds that into the generic Linux memory
 * allocation code routines via a platform independent interface (memblock, etc.).
 */
#include <linux/crash_dump.h>
#include <linux/memblock.h>
#include <linux/suspend.h>
#include <linux/acpi.h>
#include <linux/firmware-map.h>
#include <linux/sort.h>
#include <linux/memory_hotplug.h>

#include <asm/e820/api.h>
#include <asm/setup.h>

/*
 * We organize the E820 table into three main data structures:
 *
 * - 'e820_table_firmware': the original firmware version passed to us by the
 *   bootloader - not modified by the kernel. It is composed of two parts:
 *   the first 128 E820 memory entries in boot_params.e820_table and the remaining
 *   (if any) entries of the SETUP_E820_EXT nodes. We use this to:
 *
 *       - the hibernation code uses it to generate a kernel-independent CRC32
 *         checksum of the physical memory layout of a system.
 *
 * - 'e820_table_kexec': a slightly modified (by the kernel) firmware version
 *   passed to us by the bootloader - the major difference between
 *   e820_table_firmware[] and this one is that e820_table_kexec[]
 *   might be modified by the kexec itself to fake an mptable.
 *   We use this to:
 *
 *       - kexec, which is a bootloader in disguise, uses the original E820
 *         layout to pass to the kexec-ed kernel. This way the original kernel
 *         can have a restricted E820 map while the kexec()-ed kexec-kernel
 *         can have access to full memory - etc.
 *
 *         Export the memory layout via /sys/firmware/memmap. kexec-tools uses
 *         the entries to create an E820 table for the kexec kernel.
 *
 *         kexec_file_load in-kernel code uses the table for the kexec kernel.
 *
 * - 'e820_table': this is the main E820 table that is massaged by the
 *   low level x86 platform code, or modified by boot parameters, before
 *   passed on to higher level MM layers.
 *
 * Once the E820 map has been converted to the standard Linux memory layout
 * information its role stops - modifying it has no effect and does not get
 * re-propagated. So its main role is a temporary bootstrap storage of firmware
 * specific memory layout data during early bootup.
 */
static struct e820_table e820_table_init		__initdata;
static struct e820_table e820_table_kexec_init		__initdata;
static struct e820_table e820_table_firmware_init	__initdata;

struct e820_table *e820_table __refdata			= &e820_table_init;
struct e820_table *e820_table_kexec __refdata		= &e820_table_kexec_init;
struct e820_table *e820_table_firmware __refdata	= &e820_table_firmware_init;

/*
 * RUSTY-LINUX: this file is upstream's arch/x86/kernel/e820.c with the table logic removed; that logic is
 * e820_rs.rs (see its header for the list). `#line` directives keep upstream's file name and line numbers for
 * the BUG_ON()s below, so a BUG report reads exactly as upstream's.
 *
 * ARRAY_SIZE(e820_table->entries) is a build-time constant of the kernel's headers (config-dependent:
 * E820_MAX_ENTRIES = 128 + 3*MAX_NUMNODES); the Rust reads it from here.
 */
const unsigned int e820_table_max_entries = ARRAY_SIZE(e820_table_init.entries);

/* Defined in e820_rs.rs */
struct change_member;
extern int e820_update_table_rs(struct e820_table *table, u32 max_nr_entries, struct change_member *cpl,
				struct change_member **cp, struct e820_entry **ol, struct e820_entry *ne);
extern u64 e820_range_update_rs(struct e820_table *table, u64 start, u64 size,
				enum e820_type old_type, enum e820_type new_type);
extern unsigned long e820_end_ram_pfn_rs(unsigned long limit_pfn, unsigned long max_arch_pfn);
extern int e820_append_table_raw(struct boot_e820_entry *entries, u32 nr_entries);
extern int parse_memopt(char *p);
extern int parse_memmap_opt(char *str);

/* "userdef" of upstream, global here: e820_rs.rs's parse_memopt()/parse_memmap_one() set it. */
int e820_userdef __initdata;

#line 67 "arch/x86/kernel/e820.c"
/* For PCI or other memory-mapped resources */
unsigned long pci_mem_start = 0xaeedbabe;
#ifdef CONFIG_PCI
EXPORT_SYMBOL(pci_mem_start);
#endif

/*
 * e820__mapped_raw_any() and e820__mapped_any() (EXPORT_SYMBOL_GPL upstream) are defined and exported by
 * e820_rs.rs (kernel::kabi_export!, with the C definition's MODVERSIONS contract).
 */

#line 278 "arch/x86/kernel/e820.c"
struct change_member {
	/* Pointer to the original entry: */
	struct e820_entry	*entry;
	/* Address for this change point: */
	unsigned long long	addr;
};

static struct change_member	change_point_list[2*E820_MAX_ENTRIES]	__initdata;
static struct change_member	*change_point[2*E820_MAX_ENTRIES]	__initdata;
static struct e820_entry	*overlap_list[E820_MAX_ENTRIES]		__initdata;
static struct e820_entry	new_entries[E820_MAX_ENTRIES]		__initdata;

#line 321 "arch/x86/kernel/e820.c"
/*
 * The sanitiser: the algorithm is e820_update_table_rs() in e820_rs.rs. The nr_entries test and the BUG_ON stay
 * here because a BUG_ON() plants a bug-table entry naming this file and line.
 */
int __init e820__update_table(struct e820_table *table)
{
	u32 max_nr_entries = ARRAY_SIZE(table->entries);

	/* If there's only one memory region, don't bother: */
	if (table->nr_entries < 2)
		return -1;

#line 334 "arch/x86/kernel/e820.c"
	BUG_ON(table->nr_entries > max_nr_entries);

	return e820_update_table_rs(table, max_nr_entries, change_point_list, change_point, overlap_list, new_entries);
}

#line 461 "arch/x86/kernel/e820.c"
/*
 * __e820__range_update(): the BUG_ON stays here (see e820__update_table()), the algorithm is
 * e820_range_update_rs() in e820_rs.rs.
 */
static u64 __init
__e820__range_update(struct e820_table *table, u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
#line 468 "arch/x86/kernel/e820.c"
	BUG_ON(old_type == new_type);

	return e820_range_update_rs(table, start, size, old_type, new_type);
}

#line 529 "arch/x86/kernel/e820.c"
u64 __init e820__range_update(u64 start, u64 size, enum e820_type old_type, enum e820_type new_type)
{
	return __e820__range_update(e820_table, start, size, old_type, new_type);
}

u64 __init e820__range_update_table(struct e820_table *t, u64 start, u64 size,
				    enum e820_type old_type, enum e820_type new_type)
{
	return __e820__range_update(t, start, size, old_type, new_type);
}

#line 611 "arch/x86/kernel/e820.c"
static void __init e820__update_table_kexec(void)
{
	e820__update_table(e820_table_kexec);
}

#line 697 "arch/x86/kernel/e820.c"
__init void e820__reallocate_tables(void)
{
	struct e820_table *n;
	int size;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table->nr_entries;
	n = kmemdup(e820_table, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_kexec->nr_entries;
	n = kmemdup(e820_table_kexec, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_kexec = n;

	size = offsetof(struct e820_table, entries) + sizeof(struct e820_entry)*e820_table_firmware->nr_entries;
	n = kmemdup(e820_table_firmware, size, GFP_KERNEL);
	BUG_ON(!n);
	e820_table_firmware = n;
}

#line 718 "arch/x86/kernel/e820.c"
/*
 * Because of the small fixed size of struct boot_params, only the first
 * 128 E820 memory entries are passed to the kernel via boot_params.e820_table,
 * the remaining (if any) entries are passed via the SETUP_E820_EXT node of
 * struct setup_data, which is parsed here.
 */
void __init e820__memory_setup_extended(u64 phys_addr, u32 data_len)
{
	int entries;
	struct boot_e820_entry *extmap;
	struct setup_data *sdata;

	sdata = early_memremap(phys_addr, data_len);
	entries = sdata->len / sizeof(*extmap);
	extmap = (struct boot_e820_entry *)(sdata->data);

	e820_append_table_raw(extmap, entries);
	e820__update_table(e820_table);

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	early_memunmap(sdata, data_len);
	pr_info("extended physical RAM map:\n");
	e820__print_table("extended");
}

#line 745 "arch/x86/kernel/e820.c"
/*
 * Find the ranges of physical addresses that do not correspond to
 * E820 RAM areas and register the corresponding pages as 'nosave' for
 * hibernation (32-bit) or software suspend and suspend to RAM (64-bit).
 *
 * This function requires the E820 map to be sorted and without any
 * overlapping entries.
 */
void __init e820__register_nosave_regions(unsigned long limit_pfn)
{
	int i;
	u64 last_addr = 0;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type != E820_TYPE_RAM)
			continue;

		if (last_addr < entry->addr)
			register_nosave_region(PFN_DOWN(last_addr), PFN_UP(entry->addr));

		last_addr = entry->addr + entry->size;
	}

	register_nosave_region(PFN_DOWN(last_addr), limit_pfn);
}

#ifdef CONFIG_ACPI
/*
 * Register ACPI NVS memory regions, so that we can save/restore them during
 * hibernation and the subsequent resume:
 */
static int __init e820__register_nvs_regions(void)
{
	int i;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		if (entry->type == E820_TYPE_NVS)
			acpi_nvs_register(entry->addr, entry->size);
	}

	return 0;
}
core_initcall(e820__register_nvs_regions);
#endif

/*
 * Allocate the requested number of bytes with the requested alignment
 * and return (the physical address) to the caller. Also register this
 * range in the 'kexec' E820 table as a reserved range.
 *
 * This allows kexec to fake a new mptable, as if it came from the real
 * system.
 */
u64 __init e820__memblock_alloc_reserved(u64 size, u64 align)
{
	u64 addr;

	addr = memblock_phys_alloc(size, align);
	if (addr) {
		e820__range_update_table(e820_table_kexec, addr, size, E820_TYPE_RAM, E820_TYPE_RESERVED);
		pr_info("update e820_table_kexec for e820__memblock_alloc_reserved()\n");
		e820__update_table_kexec();
	}

	return addr;
}

#line 816 "arch/x86/kernel/e820.c"
#ifdef CONFIG_X86_32
# ifdef CONFIG_X86_PAE
#  define MAX_ARCH_PFN		(1ULL<<(36-PAGE_SHIFT))
# else
#  define MAX_ARCH_PFN		(1ULL<<(32-PAGE_SHIFT))
# endif
#else /* CONFIG_X86_32 */
# define MAX_ARCH_PFN MAXMEM>>PAGE_SHIFT
#endif

#line 865 "arch/x86/kernel/e820.c"
unsigned long __init e820__end_of_ram_pfn(void)
{
	return e820_end_ram_pfn_rs(MAX_ARCH_PFN, MAX_ARCH_PFN);
}

unsigned long __init e820__end_of_low_ram_pfn(void)
{
	return e820_end_ram_pfn_rs(1UL << (32 - PAGE_SHIFT), MAX_ARCH_PFN);
}

#line 875 "arch/x86/kernel/e820.c"
static void __init early_panic(char *msg)
{
	early_printk(msg);
	panic(msg);
}


#line 883 "arch/x86/kernel/e820.c"
/* parse_memopt() and parse_memmap_opt() are in e820_rs.rs */
early_param("mem", parse_memopt);
early_param("memmap", parse_memmap_opt);

#line 991 "arch/x86/kernel/e820.c"
/*
 * Called after parse_early_param(), after early parameters (such as mem=)
 * have been processed, in which case we already have an E820 table filled in
 * via the parameter callback function(s), but it's not sorted and printed yet:
 */
void __init e820__finish_early_params(void)
{
	if (e820_userdef) {
		if (e820__update_table(e820_table) < 0)
			early_panic("Invalid user supplied memory map");

		pr_info("user-defined physical RAM map:\n");
		e820__print_table("user");
	}
}

#line 1007 "arch/x86/kernel/e820.c"
static const char *__init e820_type_to_string(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RAM:		return "System RAM";
	case E820_TYPE_ACPI:		return "ACPI Tables";
	case E820_TYPE_NVS:		return "ACPI Non-volatile Storage";
	case E820_TYPE_UNUSABLE:	return "Unusable memory";
	case E820_TYPE_PRAM:		return "Persistent Memory (legacy)";
	case E820_TYPE_PMEM:		return "Persistent Memory";
	case E820_TYPE_RESERVED:	return "Reserved";
	case E820_TYPE_SOFT_RESERVED:	return "Soft Reserved";
	default:			return "Unknown E820 type";
	}
}

static unsigned long __init e820_type_to_iomem_type(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RAM:		return IORESOURCE_SYSTEM_RAM;
	case E820_TYPE_ACPI:		/* Fall-through: */
	case E820_TYPE_NVS:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	case E820_TYPE_PRAM:		/* Fall-through: */
	case E820_TYPE_PMEM:		/* Fall-through: */
	case E820_TYPE_RESERVED:	/* Fall-through: */
	case E820_TYPE_SOFT_RESERVED:	/* Fall-through: */
	default:			return IORESOURCE_MEM;
	}
}

static unsigned long __init e820_type_to_iores_desc(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_ACPI:		return IORES_DESC_ACPI_TABLES;
	case E820_TYPE_NVS:		return IORES_DESC_ACPI_NV_STORAGE;
	case E820_TYPE_PMEM:		return IORES_DESC_PERSISTENT_MEMORY;
	case E820_TYPE_PRAM:		return IORES_DESC_PERSISTENT_MEMORY_LEGACY;
	case E820_TYPE_RESERVED:	return IORES_DESC_RESERVED;
	case E820_TYPE_SOFT_RESERVED:	return IORES_DESC_SOFT_RESERVED;
	case E820_TYPE_RAM:		/* Fall-through: */
	case E820_TYPE_UNUSABLE:	/* Fall-through: */
	default:			return IORES_DESC_NONE;
	}
}

static bool __init do_mark_busy(enum e820_type type, struct resource *res)
{
	/* this is the legacy bios/dos rom-shadow + mmio region */
	if (res->start < (1ULL<<20))
		return true;

	/*
	 * Treat persistent memory and other special memory ranges like
	 * device memory, i.e. reserve it for exclusive use of a driver
	 */
	switch (type) {
	case E820_TYPE_RESERVED:
	case E820_TYPE_SOFT_RESERVED:
	case E820_TYPE_PRAM:
	case E820_TYPE_PMEM:
		return false;
	case E820_TYPE_RAM:
	case E820_TYPE_ACPI:
	case E820_TYPE_NVS:
	case E820_TYPE_UNUSABLE:
	default:
		return true;
	}
}

/*
 * Mark E820 reserved areas as busy for the resource manager:
 */

static struct resource __initdata *e820_res;

void __init e820__reserve_resources(void)
{
	int i;
	struct resource *res;
	u64 end;

	res = memblock_alloc_or_panic(sizeof(*res) * e820_table->nr_entries,
			     SMP_CACHE_BYTES);
	e820_res = res;

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = e820_table->entries + i;

		end = entry->addr + entry->size - 1;
		if (end != (resource_size_t)end) {
			res++;
			continue;
		}
		res->start = entry->addr;
		res->end   = end;
		res->name  = e820_type_to_string(entry);
		res->flags = e820_type_to_iomem_type(entry);
		res->desc  = e820_type_to_iores_desc(entry);

		/*
		 * Don't register the region that could be conflicted with
		 * PCI device BAR resources and insert them later in
		 * pcibios_resource_survey():
		 */
		if (do_mark_busy(entry->type, res)) {
			res->flags |= IORESOURCE_BUSY;
			insert_resource(&iomem_resource, res);
		}
		res++;
	}

	/* Expose the kexec e820 table to the sysfs. */
	for (i = 0; i < e820_table_kexec->nr_entries; i++) {
		struct e820_entry *entry = e820_table_kexec->entries + i;

		firmware_map_add_early(entry->addr, entry->addr + entry->size, e820_type_to_string(entry));
	}
}

/*
 * How much should we pad the end of RAM, depending on where it is?
 */
static unsigned long __init ram_alignment(resource_size_t pos)
{
	unsigned long mb = pos >> 20;

	/* To 64kB in the first megabyte */
	if (!mb)
		return 64*1024;

	/* To 1MB in the first 16MB */
	if (mb < 16)
		return 1024*1024;

	/* To 64MB for anything above that */
	return 64*1024*1024;
}

#define MAX_RESOURCE_SIZE ((resource_size_t)-1)

void __init e820__reserve_resources_late(void)
{
	int i;
	struct resource *res;

	res = e820_res;
	for (i = 0; i < e820_table->nr_entries; i++) {
		if (!res->parent && res->end)
			insert_resource_expand_to_fit(&iomem_resource, res);
		res++;
	}

	/*
	 * Try to bump up RAM regions to reasonable boundaries, to
	 * avoid stolen RAM:
	 */
	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];
		u64 start, end;

		if (entry->type != E820_TYPE_RAM)
			continue;

		start = entry->addr + entry->size;
		end = round_up(start, ram_alignment(start)) - 1;
		if (end > MAX_RESOURCE_SIZE)
			end = MAX_RESOURCE_SIZE;
		if (start >= end)
			continue;

		printk(KERN_DEBUG "e820: reserve RAM buffer [mem %#010llx-%#010llx]\n", start, end);
		reserve_region_with_split(&iomem_resource, start, end, "RAM buffer");
	}
}


#line 1219 "arch/x86/kernel/e820.c"
/*
 * Calls e820__memory_setup_default() in essence to pick up the firmware/bootloader
 * E820 map - with an optional platform quirk available for virtual platforms
 * to override this method of boot environment processing:
 */
void __init e820__memory_setup(void)
{
	char *who;

	/* This is a firmware interface ABI - make sure we don't break it: */
	BUILD_BUG_ON(sizeof(struct boot_e820_entry) != 20);

	who = x86_init.resources.memory_setup();

	memcpy(e820_table_kexec, e820_table, sizeof(*e820_table_kexec));
	memcpy(e820_table_firmware, e820_table, sizeof(*e820_table_firmware));

	pr_info("BIOS-provided physical RAM map:\n");
	e820__print_table(who);
}

#line 1240 "arch/x86/kernel/e820.c"
void __init e820__memblock_setup(void)
{
	int i;
	u64 end;

#ifdef CONFIG_MEMORY_HOTPLUG
	/*
	 * Memory used by the kernel cannot be hot-removed because Linux
	 * cannot migrate the kernel pages. When memory hotplug is
	 * enabled, we should prevent memblock from allocating memory
	 * for the kernel.
	 *
	 * ACPI SRAT records all hotpluggable memory ranges. But before
	 * SRAT is parsed, we don't know about it.
	 *
	 * The kernel image is loaded into memory at very early time. We
	 * cannot prevent this anyway. So on NUMA system, we set any
	 * node the kernel resides in as un-hotpluggable.
	 *
	 * Since on modern servers, one node could have double-digit
	 * gigabytes memory, we can assume the memory around the kernel
	 * image is also un-hotpluggable. So before SRAT is parsed, just
	 * allocate memory near the kernel image to try the best to keep
	 * the kernel away from hotpluggable memory.
	 */
	if (movable_node_is_enabled())
		memblock_set_bottom_up(true);
#endif

	/*
	 * At this point only the first megabyte is mapped for sure, the
	 * rest of the memory cannot be used for memblock resizing
	 */
	memblock_set_current_limit(ISA_END_ADDRESS);

	/*
	 * The bootstrap memblock region count maximum is 128 entries
	 * (INIT_MEMBLOCK_REGIONS), but EFI might pass us more E820 entries
	 * than that - so allow memblock resizing.
	 *
	 * This is safe, because this call happens pretty late during x86 setup,
	 * so we know about reserved memory regions already. (This is important
	 * so that memblock resizing does no stomp over reserved areas.)
	 */
	memblock_allow_resize();

	for (i = 0; i < e820_table->nr_entries; i++) {
		struct e820_entry *entry = &e820_table->entries[i];

		end = entry->addr + entry->size;
		if (end != (resource_size_t)end)
			continue;

		if (entry->type == E820_TYPE_SOFT_RESERVED)
			memblock_reserve(entry->addr, entry->size);

		if (entry->type != E820_TYPE_RAM)
			continue;

		memblock_add(entry->addr, entry->size);
	}

	/*
	 * At this point memblock is only allowed to allocate from memory
	 * below 1M (aka ISA_END_ADDRESS) up until direct map is completely set
	 * up in init_mem_mapping().
	 *
	 * KHO kernels are special and use only scratch memory for memblock
	 * allocations, but memory below 1M is ignored by kernel after early
	 * boot and cannot be naturally marked as scratch.
	 *
	 * To allow allocation of the real-mode trampoline and a few (if any)
	 * other very early allocations from below 1M forcibly mark the memory
	 * below 1M as scratch.
	 *
	 * After real mode trampoline is allocated, we clear that scratch
	 * marking.
	 */
	memblock_mark_kho_scratch(0, SZ_1M);

	/*
	 * 32-bit systems are limited to 4BG of memory even with HIGHMEM and
	 * to even less without it.
	 * Discard memory after max_pfn - the actual limit detected at runtime.
	 */
	if (IS_ENABLED(CONFIG_X86_32))
		memblock_remove(PFN_PHYS(max_pfn), -1);

	/* Throw away partial pages: */
	memblock_trim_memory(PAGE_SIZE);

	memblock_dump_all();
}

