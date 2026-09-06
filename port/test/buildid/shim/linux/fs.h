#pragma once
#include <linux/types.h>

/* Never actually exercised: this differential only ever drives freader in
 * memory-backed mode (freader_init_from_mem()) -- get_build_id_32()/64()
 * and parse_build_id() are given a real, linkable name specifically so
 * the harness can call them directly with a memory-backed Freader,
 * bypassing the file-backed path entirely (see buildid_rs.rs's own doc
 * comment on parse_build_id()). These stubs only need to COMPILE.
 */
struct address_space {
	int dummy;
};

struct file {
	struct address_space *f_mapping;
};

#define PAGE_SHIFT 12

static inline long __kernel_read(struct file *file, void *buf, size_t count, loff_t *pos)
{
	(void)file; (void)buf; (void)count; (void)pos;
	return -1;
}
