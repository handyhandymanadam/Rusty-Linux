#pragma once
/* mpi-pow.c's retained thunk (this project's mpi-pow.c, compiled as-is in
 * this harness) calls the real cond_resched() -- a no-op stand-in here,
 * same reasoning as every other kernel primitive this harness stubs. */
static inline void cond_resched(void) {}
