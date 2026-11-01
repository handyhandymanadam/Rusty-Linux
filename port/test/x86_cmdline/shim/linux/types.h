#ifndef SHIM_TYPES_H
#define SHIM_TYPES_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef uint8_t u8;
#define fallthrough __attribute__((__fallthrough__))
#ifdef WITH_BOOL
#define IS_ENABLED(x) 1
#else
#define IS_ENABLED(x) 0
#endif
#endif
