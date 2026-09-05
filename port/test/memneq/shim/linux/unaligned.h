#pragma once
#define get_unaligned(ptr) ({ \
	struct __packed_ld { __typeof__(*(ptr)) v; } __attribute__((packed, may_alias)); \
	((const struct __packed_ld *)(ptr))->v; })
