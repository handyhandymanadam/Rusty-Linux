// SPDX-License-Identifier: GPL-2.0
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * The ELF-parsing algorithm (parse_build_id()/get_build_id_32()/
 * get_build_id_64()/__build_id_parse(), plus the four EXPORT_SYMBOL_GPL
 * entry points and init_vmlinux_build_id()) is in lib/buildid_rs.rs.
 *
 * struct freader and its six helpers stay here in full: they are the I/O
 * layer, not the algorithm -- freader_get_folio()/freader_fetch() touch
 * struct file/struct folio/the page cache directly (filemap_get_folio(),
 * kmap_local_folio(), folio_test_uptodate(), secretmem_mapping(),
 * __kernel_read()), real MM/VFS coupling this port has no reason to
 * reimplement, same shape as keeping the file-backed uaccess/percpu_counter
 * layers in C for the raw-uaccess and spinlock+IRQ-state hazard classes
 * (logs/porting-hazards.md). The Rust side calls freader_init_from_file()/
 * freader_init_from_mem()/freader_fetch()/freader_cleanup() as ordinary,
 * non-static, non-exported C functions across the FFI boundary -- struct
 * freader itself stays fully opaque to Rust (56 bytes, stack-allocated by
 * the Rust caller, never read or written field-by-field there; see
 * buildid_rs.rs's own doc comment for why it is not `Mirrors`-annotated).
 * freader_get_folio()/freader_put_folio() stay `static`: only
 * freader_fetch()/freader_cleanup() call them, and neither is called from
 * Rust directly.
 */
#include <linux/buildid.h>
#include <linux/cache.h>
#include <linux/elf.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/secretmem.h>

struct freader {
	void *buf;
	u32 buf_sz;
	int err;
	union {
		struct {
			struct file *file;
			struct folio *folio;
			void *addr;
			loff_t folio_off;
			bool may_fault;
		};
		struct {
			const char *data;
			u64 data_sz;
		};
	};
};

/* Forward-declared for the same reason as every other retained-C thunk in
 * this port: -Wmissing-prototypes is fatal (-Werror) and these symbols'
 * only caller outside this file is Rust, via FFI.
 */
void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
			     struct file *file, bool may_fault);
void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz);
const void *freader_fetch(struct freader *r, loff_t file_off, size_t sz);
void freader_cleanup(struct freader *r);
int freader_get_err(const struct freader *r);

void freader_init_from_file(struct freader *r, void *buf, u32 buf_sz,
			     struct file *file, bool may_fault)
{
	memset(r, 0, sizeof(*r));
	r->buf = buf;
	r->buf_sz = buf_sz;
	r->file = file;
	r->may_fault = may_fault;
}

void freader_init_from_mem(struct freader *r, const char *data, u64 data_sz)
{
	memset(r, 0, sizeof(*r));
	r->data = data;
	r->data_sz = data_sz;
}

static void freader_put_folio(struct freader *r)
{
	if (!r->folio)
		return;
	kunmap_local(r->addr);
	folio_put(r->folio);
	r->folio = NULL;
}

static int freader_get_folio(struct freader *r, loff_t file_off)
{
	/* check if we can just reuse current folio */
	if (r->folio && file_off >= r->folio_off &&
	    file_off < r->folio_off + folio_size(r->folio))
		return 0;

	freader_put_folio(r);

	/* only use page cache lookup - fail if not already cached */
	r->folio = filemap_get_folio(r->file->f_mapping, file_off >> PAGE_SHIFT);

	if (IS_ERR(r->folio) || !folio_test_uptodate(r->folio)) {
		if (!IS_ERR(r->folio))
			folio_put(r->folio);
		r->folio = NULL;
		return -EFAULT;
	}

	r->folio_off = folio_pos(r->folio);
	r->addr = kmap_local_folio(r->folio, 0);

	return 0;
}

const void *freader_fetch(struct freader *r, loff_t file_off, size_t sz)
{
	size_t folio_sz;

	/* provided internal temporary buffer should be sized correctly */
	if (WARN_ON(r->buf && sz > r->buf_sz)) {
		r->err = -E2BIG;
		return NULL;
	}

	if (unlikely(file_off + sz < file_off)) {
		r->err = -EOVERFLOW;
		return NULL;
	}

	/* working with memory buffer is much more straightforward */
	if (!r->buf) {
		if (file_off + sz > r->data_sz) {
			r->err = -ERANGE;
			return NULL;
		}
		return r->data + file_off;
	}

	/* reject secretmem folios created with memfd_secret() */
	if (secretmem_mapping(r->file->f_mapping)) {
		r->err = -EFAULT;
		return NULL;
	}

	/* use __kernel_read() for sleepable context */
	if (r->may_fault) {
		ssize_t ret;

		ret = __kernel_read(r->file, r->buf, sz, &file_off);
		if (ret != sz) {
			r->err = (ret < 0) ? ret : -EIO;
			return NULL;
		}
		return r->buf;
	}

	/* fetch or reuse folio for given file offset */
	r->err = freader_get_folio(r, file_off);
	if (r->err)
		return NULL;

	/* if requested data is crossing folio boundaries, we have to copy
	 * everything into our local buffer to keep a simple linear memory
	 * access interface
	 */
	folio_sz = folio_size(r->folio);
	if (file_off + sz > r->folio_off + folio_sz) {
		int part_sz = r->folio_off + folio_sz - file_off;

		/* copy the part that resides in the current folio */
		memcpy(r->buf, r->addr + (file_off - r->folio_off), part_sz);

		/* fetch next folio */
		r->err = freader_get_folio(r, r->folio_off + folio_sz);
		if (r->err)
			return NULL;

		/* copy the rest of requested data */
		memcpy(r->buf + part_sz, r->addr, sz - part_sz);

		return r->buf;
	}

	/* if data fits in a single folio, just return direct pointer */
	return r->addr + (file_off - r->folio_off);
}

void freader_cleanup(struct freader *r)
{
	if (!r->buf)
		return; /* non-file-backed mode */

	freader_put_folio(r);
}

/* Accessor for the opaque struct freader's `err` field -- the Rust side
 * never reads any field of struct freader directly (see buildid_rs.rs's
 * module doc comment for why the whole struct is a sized-but-opaque
 * mirror), including this one; a proper accessor keeps it that way rather
 * than hardcoding the field's byte offset on the Rust side.
 */
int freader_get_err(const struct freader *r)
{
	return r->err;
}
