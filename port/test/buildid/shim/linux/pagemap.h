#pragma once
#include <linux/fs.h>
#include <stddef.h>

/* Never actually exercised -- see linux/fs.h's comment. */
struct folio {
	int dummy;
};

#define IS_ERR(x) false

static inline struct folio *filemap_get_folio(struct address_space *m, unsigned long index)
{
	(void)m; (void)index;
	return (struct folio *)0;
}

static inline bool folio_test_uptodate(struct folio *f) { (void)f; return false; }
static inline size_t folio_size(struct folio *f) { (void)f; return 4096; }
static inline loff_t folio_pos(struct folio *f) { (void)f; return 0; }
static inline void *kmap_local_folio(struct folio *f, size_t offset) { (void)f; (void)offset; return (void *)0; }
static inline void kunmap_local(const void *addr) { (void)addr; }
static inline void folio_put(struct folio *f) { (void)f; }
