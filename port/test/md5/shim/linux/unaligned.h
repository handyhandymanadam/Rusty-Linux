#pragma once
#include <linux/types.h>
#include <string.h>

/* This harness builds and runs on x86-64, which is little-endian -- the same
 * target the kernel builds md5.c for. So the LE conversions below really are
 * identity operations on this host, exactly as they are in the kernel; they
 * are not stubs that skip the byteswap, they are what le32_to_cpu_array()
 * etc. reduce to on this architecture. */

static inline __le64 cpu_to_le64(u64 v)
{
	return (__le64)v;
}

static inline void le32_to_cpu_array(u32 *buf, unsigned int words)
{
	(void)buf;
	(void)words;
}

static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
	(void)buf;
	(void)words;
}
