// SPDX-License-Identifier: GPL-2.0
/*
 * SHA-1 and HMAC-SHA1 library functions
 *
 * WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * Every exported function is in lib/crypto/sha1_rs.rs. What stays here is
 * the ARCHITECTURE DISPATCH -- same shape and same reason as
 * lib/crypto/sha512.c and lib/crypto/blake2s.c (see either's own header
 * comment, and logs/c-entry-rule.md):
 *
 *   - a static_call, defined and updated inside $(SRCARCH)/sha1.h, patched
 *     at boot to select the SHA-NI/AVX2/AVX/SSSE3 core;
 *   - kernel_fpu_begin()/kernel_fpu_end() around the SIMD state;
 *   - asmlinkage calls into the four x86 cores.
 *
 * $(SRCARCH)/sha1.h defines sha1_blocks() as a `static` function on top of
 * those, so it has no symbol for the Rust to call. This file gives it one,
 * in sha1_blocks_dispatch().
 *
 * THE GENERIC COMPRESSION IS STILL REACHED. Every one of
 * sha1_blocks_{ssse3,avx,avx2,ni} falls back to sha1_blocks_generic()
 * whenever irq_fpu_usable() is false, so the Rust body below runs on a
 * normal machine, not only on an architecture without these extensions.
 */

#include <crypto/hmac.h>
#include <crypto/sha1.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

/* lib/crypto/sha1_rs.rs. */
void rust_sha1_blocks_generic(struct sha1_block_state *state,
			      const u8 *data, size_t nblocks);

/* Forward-declared for the same reason as blake2s_compress_dispatch()/
 * sha512_blocks_dispatch(): config-full's -Wmissing-prototypes is fatal
 * (-Werror) and this symbol's only caller is Rust, via FFI.
 */
void sha1_blocks_dispatch(struct sha1_block_state *state,
			  const u8 *data, size_t nblocks);

/*
 * The name $(SRCARCH)/sha1.h expects to fall back to. A tail call to the
 * Rust body.
 */
static void __maybe_unused
sha1_blocks_generic(struct sha1_block_state *state, const u8 *data,
		    size_t nblocks)
{
	rust_sha1_blocks_generic(state, data, nblocks);
}

#ifdef CONFIG_CRYPTO_LIB_SHA1_ARCH
#include "sha1.h" /* $(SRCARCH)/sha1.h */
#else
#define sha1_blocks sha1_blocks_generic
#endif

/*
 * THE REASON THIS FILE EXISTS. sha1_blocks() is `static` -- either the arch
 * header's static_call dispatcher or the macro above -- so it has no
 * symbol. This is that symbol, for lib/crypto/sha1_rs.rs to call. It is
 * not EXPORT_SYMBOL: nothing outside lib/crypto has ever been able to
 * reach it.
 */
void sha1_blocks_dispatch(struct sha1_block_state *state,
			  const u8 *data, size_t nblocks)
{
	sha1_blocks(state, data, nblocks);
}

#ifdef sha1_mod_init_arch
static int __init sha1_mod_init(void)
{
	sha1_mod_init_arch();
	return 0;
}
subsys_initcall(sha1_mod_init);

static void __exit sha1_mod_exit(void)
{
}
module_exit(sha1_mod_exit);
#endif

MODULE_DESCRIPTION("SHA-1 and HMAC-SHA1 library functions");
MODULE_LICENSE("GPL");
