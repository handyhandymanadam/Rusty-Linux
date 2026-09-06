#pragma once
/* mpih-div.c never allocates; slab.h is only pulled in transitively via
 * mpi-internal.h and needs to exist, not do anything. */
