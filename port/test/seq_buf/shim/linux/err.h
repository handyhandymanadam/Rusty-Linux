#pragma once
#include <linux/types.h>
#define MAX_ERRNO 4095
static inline bool IS_ERR(const void *ptr)
{
	return (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}
