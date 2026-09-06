#pragma once
#include <linux/types.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define unlikely(x) __builtin_expect(!!(x), 0)
#define __maybe_unused __attribute__((__unused__))
