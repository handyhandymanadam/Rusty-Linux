#pragma once
#include <stddef.h>
#define noinline __attribute__((noinline))
#ifndef OPTIMIZER_HIDE_VAR
#define OPTIMIZER_HIDE_VAR(var) __asm__ ("" : "=r" (var) : "0" (var))
#endif
