/* SPDX-License-Identifier: GPL-2.0-only */
/* Real (non-inline) definitions for the simulated scatterlist API
 * declared in shim/linux/scatterlist.h -- see that header's own comment
 * for why this is a from-scratch simulation and why the algorithm below
 * matches the real lib/scatterlist.c's __offset/__remaining accounting. */
#include <linux/scatterlist.h>
#include <string.h>

int sg_nents_for_len(struct scatterlist *sg, uint64_t len)
{
	int nents = 0;
	uint64_t total = 0;

	while (total < len) {
		total += sg[nents].length;
		nents++;
	}
	return nents;
}

void sg_miter_start(struct sg_mapping_iter *miter, struct scatterlist *sgl,
		    unsigned int nents, unsigned int flags)
{
	memset(miter, 0, sizeof(*miter));
	miter->piter.sg = sgl;
	miter->piter.__nents = nents;
	miter->__flags = flags;
}

void sg_miter_stop(struct sg_mapping_iter *miter)
{
	if (miter->addr) {
		miter->__offset += (unsigned int)miter->consumed;
		miter->__remaining -= (unsigned int)miter->consumed;
		miter->page = NULL;
		miter->addr = NULL;
		miter->length = 0;
		miter->consumed = 0;
	}
}

bool sg_miter_next(struct sg_mapping_iter *miter)
{
	sg_miter_stop(miter);

	if (!miter->__remaining) {
		if (miter->piter.__nents == 0)
			return false;
		miter->__offset = 0;
		miter->__remaining = miter->piter.sg->length;
		miter->piter.sg++;
		miter->piter.__nents--;
	}

	miter->addr = (char *)miter->piter.sg[-1].buf + miter->__offset;
	miter->length = miter->consumed = miter->__remaining;
	return true;
}
