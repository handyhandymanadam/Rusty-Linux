/* kernel shim for the iov_iter differential: struct iov_iter and the folio queue as in 6.18.49 (the glue static_asserts the real offsets),
 * plus the few helpers the ported functions use. */
#ifndef KSHIM_H
#define KSHIM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64; typedef int64_t loff_t;
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define MAX_RW_COUNT (2147483647 & ~(PAGE_SIZE - 1))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define EXPORT_SYMBOL(x)
#define EXPORT_SYMBOL_GPL(x)
#define __user
#define min(a, b) ({ __typeof__(a) a_ = (a); __typeof__(b) b_ = (b); a_ < b_ ? a_ : b_; })
#define umin(a, b) ({ unsigned long long a_ = (a), b_ = (b); a_ < b_ ? a_ : b_; })
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define offset_in_page(p) ((unsigned long)(p) & (PAGE_SIZE - 1))
extern int warn_count, bug_count;
#define WARN_ON(c) ({ int c_ = !!(c); if (c_) warn_count++; c_; })
#define WARN_ON_ONCE(c) WARN_ON(c)
#define BUG() do { bug_count++; longjmp(bug_jmp, 1); } while (0)
#include <setjmp.h>
extern jmp_buf bug_jmp;
#define BUILD_BUG_ON(c) _Static_assert(!(c), "bug")
#define READ 0
#define WRITE 1

struct iovec { void *iov_base; size_t iov_len; };
struct kvec { void *iov_base; size_t iov_len; };
struct bio_vec { void *bv_page; unsigned int bv_len; unsigned int bv_offset; };
struct xarray;
#define PAGEVEC_SIZE 31
struct folio_queue {
	void *vec[PAGEVEC_SIZE + 1];
	u8 orders[PAGEVEC_SIZE];
	struct folio_queue *next, *prev;
	unsigned long marks, marks2;
};
static inline unsigned int folioq_nr_slots(const struct folio_queue *q) { return PAGEVEC_SIZE; }
static inline size_t folioq_folio_size(const struct folio_queue *q, unsigned int slot) { return PAGE_SIZE << q->orders[slot]; }

enum iter_type { ITER_UBUF, ITER_IOVEC, ITER_BVEC, ITER_KVEC, ITER_FOLIOQ, ITER_XARRAY, ITER_DISCARD };
struct iov_iter_state { size_t iov_offset; size_t count; unsigned long nr_segs; };
struct iov_iter {
	u8 iter_type; bool nofault; bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov; const struct kvec *kvec; const struct bio_vec *bvec;
				const struct folio_queue *folioq; struct xarray *xarray; void __user *ubuf;
			};
			size_t count;
		};
	};
	union { unsigned long nr_segs; u8 folioq_slot; loff_t xarray_start; };
};
static inline bool iter_is_ubuf(const struct iov_iter *i) { return i->iter_type == ITER_UBUF; }
static inline bool iter_is_iovec(const struct iov_iter *i) { return i->iter_type == ITER_IOVEC; }
static inline bool iov_iter_is_kvec(const struct iov_iter *i) { return i->iter_type == ITER_KVEC; }
static inline bool iov_iter_is_bvec(const struct iov_iter *i) { return i->iter_type == ITER_BVEC; }
static inline bool iov_iter_is_discard(const struct iov_iter *i) { return i->iter_type == ITER_DISCARD; }
static inline bool iov_iter_is_folioq(const struct iov_iter *i) { return i->iter_type == ITER_FOLIOQ; }
static inline bool iov_iter_is_xarray(const struct iov_iter *i) { return i->iter_type == ITER_XARRAY; }
static inline const struct iovec *iter_iov(const struct iov_iter *iter) { return iter->iter_type == ITER_UBUF ? &iter->__ubuf_iovec : iter->__iov; }

void iov_iter_advance(struct iov_iter *i, size_t size);
void iov_iter_revert(struct iov_iter *i, size_t unroll);
size_t iov_iter_single_seg_count(const struct iov_iter *i);
unsigned long iov_iter_alignment(const struct iov_iter *i);
unsigned long iov_iter_gap_alignment(const struct iov_iter *i);
int iov_iter_npages(const struct iov_iter *i, int maxpages);
void iov_iter_restore(struct iov_iter *i, struct iov_iter_state *state);
#endif
