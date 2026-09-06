#pragma once
#include <linux/types.h>
struct address_space;
static inline bool secretmem_mapping(struct address_space *m) { (void)m; return false; }
