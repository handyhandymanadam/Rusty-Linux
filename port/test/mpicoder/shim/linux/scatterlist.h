#pragma once
/* Trimmed reproduction of include/linux/scatterlist.h: only the entry
 * points and struct fields mpicoder.c reads directly, plus a from-scratch
 * SIMULATED implementation of sg_nents_for_len()/sg_miter_start()/
 * _next()/_stop() for this flat-buffer, no-real-pages userspace harness.
 *
 * struct scatterlist's OWN layout is whatever this shim wants (mpicoder.c
 * never dereferences it, only forwards the pointer -- see
 * mpicoder_rs.rs's own module doc comment) -- but struct sg_mapping_iter
 * MUST match the real kernel layout exactly: mpicoder_rs.rs's own
 * SgMappingIter/SgPageIter mirror that real layout field-for-field, and
 * the SAME compiled sg_miter_*() functions below are called by both the
 * C arm (using this header's struct) and the Rust arm (using its own,
 * independently-defined but identically-laid-out struct) -- so this
 * header's struct sg_mapping_iter/sg_page_iter must have exactly these
 * fields, in this order, with no shim-only additions.
 *
 * The simulated sg_miter_* below reproduces the real algorithm's
 * __offset/__remaining partial-consumption accounting exactly (verified
 * against lib/scatterlist.c before writing this) -- it just treats one
 * whole scatterlist entry as one "page" per sg_miter_next() call, since
 * userspace has no real page-mapping concept to simulate. This is a
 * STRONGER test than real 4 KiB pages would give for the tiny buffers
 * this harness exercises: small deliberately-chosen chunk sizes force
 * many sg_miter_next() calls and cross many entry boundaries, exactly
 * the shape mpi_write_to_sgl()/mpi_read_raw_from_sgl()'s own loops exist
 * to handle.
 */
#include <linux/types.h>
#include <string.h>
#include <stdbool.h>

struct scatterlist {
	void *buf;
	unsigned int length;
};

struct sg_page_iter {
	struct scatterlist *sg;
	unsigned int sg_pgoffset;
	unsigned int __nents;
	int __pg_advance;
};

struct sg_mapping_iter {
	void *page;
	void *addr;
	size_t length;
	size_t consumed;
	struct sg_page_iter piter;
	unsigned int __offset;
	unsigned int __remaining;
	unsigned int __flags;
};

#define SG_MITER_ATOMIC  (1 << 0)
#define SG_MITER_TO_SG   (1 << 1)
#define SG_MITER_FROM_SG (1 << 2)

/* Real (non-`static inline`) functions -- port/test/mpicoder/shim/sgl_shim.c
 * -- both arms (the pristine C, compiled standalone, and the Rust arm,
 * linked separately) call these as external symbols, so they cannot be
 * header-only `static inline`. */
int sg_nents_for_len(struct scatterlist *sg, uint64_t len);
void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl,
		    unsigned int nents, unsigned int flags);
void sg_miter_stop(struct sg_mapping_iter *miter);
bool sg_miter_next(struct sg_mapping_iter *miter);
