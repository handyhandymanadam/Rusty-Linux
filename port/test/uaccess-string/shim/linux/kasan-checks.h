#pragma once
#include <stddef.h>
static inline void kasan_check_write(const void *p, size_t n) { (void)p; (void)n; }
