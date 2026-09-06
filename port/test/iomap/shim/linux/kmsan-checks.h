#pragma once
/* CONFIG_KMSAN is off on both of this project's configs -- these are
 * real, no-op static inlines there too (include/linux/kmsan-checks.h),
 * so this shim just matches that.
 */
#include <linux/types.h>
static inline void kmsan_check_memory(const void *address, size_t size) { (void)address; (void)size; }
static inline void kmsan_unpoison_memory(const void *address, size_t size) { (void)address; (void)size; }
#define __no_kmsan_checks
