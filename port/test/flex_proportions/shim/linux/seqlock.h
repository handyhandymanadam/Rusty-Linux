#pragma once
#include <linux/seqlock_types.h>

static inline void seqcount_init(seqcount_t *s) { s->sequence = 0; }

static inline void write_seqcount_begin(seqcount_t *s) { s->sequence++; }
static inline void write_seqcount_end(seqcount_t *s) { s->sequence++; }

static inline unsigned int read_seqcount_begin(const seqcount_t *s)
{
	unsigned int seq;

	while ((seq = s->sequence) & 1)
		;
	return seq;
}

static inline int read_seqcount_retry(const seqcount_t *s, unsigned int start)
{
	return s->sequence != start;
}
