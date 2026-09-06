#pragma once
/* Trimmed reproduction of include/linux/err.h -- see mpicoder_rs.rs's own
 * module doc comment for why this is a bare pointer-encode, no kernel
 * machinery involved. */
#define MAX_ERRNO 4095

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long)ptr;
}

static inline int IS_ERR(const void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}
