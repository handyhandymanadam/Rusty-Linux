#pragma once
#include <stdio.h>
/* WARN_ONCE() never changes ___ratelimit()'s control flow or observable
 * state -- it is purely diagnostic. This shim doesn't need to reproduce
 * the real bug-table/"only once" machinery (that's exactly why the real
 * WARN_ONCE stays in the retained C thunk, rust_ratelimit_warn_once() --
 * see lib/ratelimit.c/ratelimit_rs.rs); it only needs to not diverge
 * either arm's return value or struct state. */
#define WARN_ONCE(condition, format, ...) \
	do { if (condition) fprintf(stderr, "WARN_ONCE: " format, ##__VA_ARGS__); } while (0)
