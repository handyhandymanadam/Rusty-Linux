// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PORTED TO RUST. WHAT IS LEFT OF THIS FILE, AND WHY
 *
 * Every function this file used to define (mpi_alloc, mpi_alloc_limb_space,
 * mpi_free_limb_space, mpi_assign_limb_space, mpi_resize, mpi_free, mpi_copy)
 * is now in lib/crypto/mpi/mpiutil_rs.rs. What stays here is kmalloc()/
 * kcalloc()/kfree()/kfree_sensitive() -- since 6.10's allocation profiling
 * these are macros over a `static inline` with no linkable symbol, so the
 * allocating/freeing calls have to stay in a small retained C thunk.
 * logs/allocation.md documents this as a standing, undesigned exception
 * across this project. Same shape as lib/generic-radix-tree.c's
 * rust_genradix_alloc_node()/_free_node().
 *
 * Four thunks, not one alloc/free pair, because this file has four distinct
 * allocation shapes: a fixed-size struct, a byte-length buffer, a
 * zero-initialized buffer, and two different frees (kfree vs
 * kfree_sensitive, which differ in whether they wipe the memory first --
 * mpi_free() itself chooses between them depending on a flag, so both have
 * to be reachable).
 */

#include <linux/module.h>
#include <linux/slab.h>

/* config-full's -Wmissing-prototypes is fatal (-Werror); Rust FFI callers
 * give the compiler nothing else to infer a prototype from. Same shape as
 * lib/crypto/blake2s.c's blake2s_compress_dispatch(). */
void *rust_mpi_kmalloc(size_t len);
void *rust_mpi_kcalloc(size_t n, size_t size);
void rust_mpi_kfree(void *p);
void rust_mpi_kfree_sensitive(void *p);

void *rust_mpi_kmalloc(size_t len)
{
	return kmalloc(len, GFP_KERNEL);
}

void *rust_mpi_kcalloc(size_t n, size_t size)
{
	return kcalloc(n, size, GFP_KERNEL);
}

void rust_mpi_kfree(void *p)
{
	kfree(p);
}

void rust_mpi_kfree_sensitive(void *p)
{
	kfree_sensitive(p);
}

/* MPILIB is tristate (CONFIG_MPILIB=m is real), and this is the only file
 * in lib/crypto/mpi/ that carries these -- kept here rather than moved to
 * kabi_modinfo! because this file, unlike a fully-deleted one, still
 * compiles. */
MODULE_DESCRIPTION("Multiprecision maths library");
MODULE_LICENSE("GPL");
