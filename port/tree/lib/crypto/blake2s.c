// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * The BLAKE2s algorithm, and both exported entry points, are in
 * lib/crypto/blake2s_rs.rs. What stays here is the ARCHITECTURE DISPATCH,
 * and it stays because it is made of three things Rust cannot express in
 * this kernel:
 *
 *   - two jump labels, defined and consulted inside that header, which are
 *     patched at boot to select the SIMD core;
 *   - kernel_fpu_begin()/kernel_fpu_end(), which disable preemption around
 *     the SIMD state;
 *   - asmlinkage calls into the SSSE3 and AVX-512 cores.
 *
 * $(SRCARCH)/blake2s.h defines blake2s_compress() as a `static` function on
 * top of those, so it has no symbol for the Rust to call. This file gives it
 * one, in blake2s_compress_dispatch(), and that is the whole of the
 * arrangement. logs/c-entry-rule.md records it as the pattern for the rest
 * of lib/crypto, which forks on SIMD the same way.
 *
 * THE GENERIC COMPRESSION IS STILL REACHED. It is not dead code on x86-64:
 * blake2s_compress() falls back to it whenever may_use_simd() is false --
 * hard IRQ context, for one -- so the Rust body below runs on a normal
 * machine, not only on an architecture without SIMD. Upstream's own
 * blake2s KUnit suite has a case for exactly that, and it is the only case
 * that notices when the Rust body is sabotaged.
 */

#include <crypto/blake2s.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/types.h>

/* lib/crypto/blake2s_rs.rs. */
void rust_blake2s_compress_generic(struct blake2s_state *state, const u8 *block,
				   size_t nblocks, const u32 inc);

/* Forward-declared for the same reason: config-full's -Wmissing-prototypes
 * is fatal (-Werror) and neither this symbol's only caller (Rust, via FFI)
 * nor its lack of an EXPORT_SYMBOL gives the compiler anything else to
 * infer a prototype from. Found when config-full was rebuilt for the first
 * time since this file was added -- config-fast does not enable the
 * warning as an error, which is why it went unnoticed until now. */
void blake2s_compress_dispatch(struct blake2s_state *state, const u8 *block,
			       size_t nblocks, const u32 inc);

/*
 * The name $(SRCARCH)/blake2s.h expects to fall back to. A tail call to the
 * Rust body. Upstream's version also carried a debug-only assertion on
 * nblocks and inc; it moved into the Rust with the body, and
 * rig/guard-except.txt records that.
 */
static void __maybe_unused
blake2s_compress_generic(struct blake2s_state *state, const u8 *block,
			 size_t nblocks, const u32 inc)
{
	rust_blake2s_compress_generic(state, block, nblocks, inc);
}

#ifdef CONFIG_CRYPTO_LIB_BLAKE2S_ARCH
#include "blake2s.h" /* $(SRCARCH)/blake2s.h */
#else
#define blake2s_compress blake2s_compress_generic
#endif

/*
 * THE REASON THIS FILE EXISTS. blake2s_compress() is `static` -- either the
 * arch header's SIMD dispatcher or the macro above -- so it has no symbol.
 * This is that symbol, for lib/crypto/blake2s_rs.rs to call. It is not
 * EXPORT_SYMBOL: nothing outside lib/crypto has ever been able to reach it,
 * and giving it away would widen the ABI the port is supposed to preserve.
 */
void blake2s_compress_dispatch(struct blake2s_state *state, const u8 *block,
			       size_t nblocks, const u32 inc)
{
	blake2s_compress(state, block, nblocks, inc);
}

#ifdef blake2s_mod_init_arch
static int __init blake2s_mod_init(void)
{
	blake2s_mod_init_arch();
	return 0;
}
subsys_initcall(blake2s_mod_init);
#endif

MODULE_DESCRIPTION("BLAKE2s hash function");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
