/* Userspace stand-ins for what port/pristine/arch/x86/kernel/e820.c and e820_glue.c need from the kernel.
 * Every number is asserted against the Rust file's constants (e820_rs.rs) and against the kernel's own headers
 * (consts_check.py, layout-check.c); this file is not trusted: a wrong value here shows as a C != Rust mismatch.
 * -DEMAX=n sets E820_MAX_ENTRIES, -DHP=1 sets CONFIG_MEMORY_HOTPLUG. */
#ifndef E820_SHIM_H
#define E820_SHIM_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef unsigned long long u64;
typedef uint8_t __u8; typedef uint16_t __u16; typedef uint32_t __u32; typedef unsigned long long __u64;
#define __init
#define __initdata
#define __refdata
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ULLONG_MAX (~0ULL)
#define EINVAL 22
#define PAGE_SHIFT 12
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define early_param(a, b)
#define fallthrough __attribute__((fallthrough))
#define cond_resched() do { } while (0)
#define CONFIG_64BIT 1
#define CONFIG_X86_64 1
#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS 1
#define IS_ENABLED(x) 0

#define KERN_SOH "\001"
#define KERN_ERR KERN_SOH "3"
#define KERN_WARNING KERN_SOH "4"
#define KERN_INFO KERN_SOH "6"
#define KERN_DEBUG KERN_SOH "7"
#define KERN_CONT KERN_SOH "c"
int _printk(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
#define printk _printk
#define pr_err(fmt, ...) printk(KERN_ERR fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) printk(KERN_WARNING fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
#define pr_cont(fmt, ...) printk(KERN_CONT fmt, ##__VA_ARGS__)

/* BUG_ON: record file:line and longjmp out (the kernel never returns from it). */
extern jmp_buf g_bug_jmp; extern const char *g_bug_file; extern int g_bug_line; extern int g_bug_armed;
void bug_hit(const char *file, int line);
#define BUG_ON(cond) do { if (unlikely(cond)) bug_hit(__FILE__, __LINE__); } while (0)

#if HP
#define CONFIG_MEMORY_HOTPLUG 1
#endif

enum e820_type {
	E820_TYPE_RAM = 1, E820_TYPE_RESERVED = 2, E820_TYPE_ACPI = 3, E820_TYPE_NVS = 4, E820_TYPE_UNUSABLE = 5,
	E820_TYPE_PMEM = 7, E820_TYPE_PRAM = 12, E820_TYPE_SOFT_RESERVED = 0xefffffff,
};
struct e820_entry { u64 addr; u64 size; enum e820_type type; } __attribute__((packed));
struct boot_e820_entry { __u64 addr; __u64 size; __u32 type; } __attribute__((packed));
#define E820_MAX_ENTRIES EMAX
struct e820_table { __u32 nr_entries; struct e820_entry entries[E820_MAX_ENTRIES]; };
_Static_assert(sizeof(struct e820_entry) == 20 && sizeof(struct boot_e820_entry) == 20, "entry size");
_Static_assert(offsetof(struct e820_table, entries) == 4, "entries offset");
#define LOWMEMSIZE() (0x9f000)
#define HIGH_MEMORY 0x00100000

/* boot_params: only the fields e820__memory_setup_default() reads, at their real offsets (asserted) */
struct boot_params {
	struct { u8 pad0[2]; u16 ext_mem_k; u8 pad1[0x1e0 - 4]; } screen_info;
	__u32 alt_mem_k; u8 pad2[4]; __u8 e820_entries; u8 pad3[0x2d0 - 0x1e9];
	struct boot_e820_entry e820_table[128];
	u8 pad4[4096 - 0x2d0 - 128 * 20];
};
_Static_assert(offsetof(struct boot_params, e820_entries) == 0x1e8 && offsetof(struct boot_params, e820_table) == 0x2d0 &&
	offsetof(struct boot_params, alt_mem_k) == 0x1e0 && offsetof(struct boot_params, screen_info.ext_mem_k) == 2 &&
	sizeof(struct boot_params) == 4096, "boot_params layout");
extern struct boot_params boot_params;
extern unsigned long max_pfn;
extern unsigned long g_maxmem;
#define MAXMEM g_maxmem
extern u64 max_mem_size;
unsigned long long memparse(const char *ptr, char **retptr);
unsigned long long simple_strtoull(const char *cp, char **endp, unsigned int base);
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *), void (*swap)(void *, void *, int));
typedef int (*cmp_func_t)(const void *, const void *);
typedef void (*swap_func_t)(void *, void *, int size);
typedef int (*cmp_r_func_t)(const void *, const void *, const void *);
typedef void (*swap_r_func_t)(void *, void *, int size, const void *);
#endif
