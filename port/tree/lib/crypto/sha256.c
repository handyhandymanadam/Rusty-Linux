// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHA-224, SHA-256, HMAC-SHA224, and HMAC-SHA256 library functions
 *
 * WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * Every exported function is in lib/crypto/sha256_rs.rs. What stays here is
 * the ARCHITECTURE DISPATCH -- same shape and reason as lib/crypto/sha1.c
 * and lib/crypto/sha512.c (see either's own header comment, and
 * logs/c-entry-rule.md), but with a SECOND, independent dispatcher:
 *
 *   - sha256_blocks(): a static_call selecting the SHA-NI/AVX2/AVX/SSSE3
 *     compression core, patched at boot -- identical shape to sha1/sha512.
 *   - sha256_finup_2x_arch(): a static branch (`have_sha_ni`) gating a
 *     SEPARATE asmlinkage routine that computes two independent digests
 *     from a shared prefix in one interleaved pass. Nothing about it goes
 *     through sha256_blocks() or the static_call above -- it is its own
 *     hook, with its own generic (sequential, non-interleaved) fallback.
 *
 * Both are `static` in $(SRCARCH)/sha256.h, so both need a symbol here for
 * the Rust to call: sha256_blocks_dispatch() and sha256_finup_2x_dispatch()
 * (plus sha256_finup_2x_is_optimized_dispatch() for the query-only sibling).
 *
 * THE GENERIC PATHS ARE STILL REACHED. sha256_blocks_{ssse3,avx,avx2,ni}
 * fall back to sha256_blocks_generic() whenever irq_fpu_usable() is false;
 * sha256_finup_2x_arch() falls back to `false` (meaning: use the Rust's own
 * sequential two-call implementation) whenever SHA-NI isn't available or
 * `len` is out of the asm routine's accepted range.
 */

#include <crypto/hmac.h>
#include <crypto/sha2.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

/* lib/crypto/sha256_rs.rs. */
void rust_sha256_blocks_generic(struct sha256_block_state *state,
				const u8 *data, size_t nblocks);

/* Forward-declared for the same reason as sha1_blocks_dispatch()/
 * sha512_blocks_dispatch(): config-full's -Wmissing-prototypes is fatal
 * and these symbols' only caller is Rust, via FFI.
 */
void sha256_blocks_dispatch(struct sha256_block_state *state,
			    const u8 *data, size_t nblocks);
bool sha256_finup_2x_dispatch(const struct __sha256_ctx *ctx,
			      const u8 *data1, const u8 *data2, size_t len,
			      u8 *out1, u8 *out2);
bool sha256_finup_2x_is_optimized_dispatch(void);

/*
 * The name $(SRCARCH)/sha256.h expects to fall back to. A tail call to the
 * Rust body.
 */
static void __maybe_unused
sha256_blocks_generic(struct sha256_block_state *state, const u8 *data,
		      size_t nblocks)
{
	rust_sha256_blocks_generic(state, data, nblocks);
}

#if defined(CONFIG_CRYPTO_LIB_SHA256_ARCH) && !defined(__DISABLE_EXPORTS)
#include "sha256.h" /* $(SRCARCH)/sha256.h */
#else
#define sha256_blocks sha256_blocks_generic
#endif

/*
 * THE REASON THIS FILE EXISTS. sha256_blocks() is `static` -- either the
 * arch header's static_call dispatcher or the macro above -- so it has no
 * symbol. This is that symbol, for lib/crypto/sha256_rs.rs to call. It is
 * not EXPORT_SYMBOL: nothing outside lib/crypto has ever been able to reach
 * it.
 */
void sha256_blocks_dispatch(struct sha256_block_state *state,
			    const u8 *data, size_t nblocks)
{
	sha256_blocks(state, data, nblocks);
}

/*
 * Pre-boot environment (as indicated by __DISABLE_EXPORTS being defined)
 * doesn't need either HMAC support or interleaved hashing support -- kept
 * from the upstream C's own structure, though this project's configs never
 * define __DISABLE_EXPORTS (verified: all of sha256_finup_2x's symbols are
 * present in every build here).
 */
#ifndef __DISABLE_EXPORTS

/*
 * $(SRCARCH)/sha256.h defines its own sha256_finup_2x_arch() under this same
 * name, via `#define sha256_finup_2x_arch sha256_finup_2x_arch` -- the same
 * self-referential-macro trick sha256_mod_init_arch uses -- which is why
 * this generic fallback is guarded by #ifndef rather than #else.
 */
#ifndef sha256_finup_2x_arch
static bool sha256_finup_2x_arch(const struct __sha256_ctx *ctx,
				 const u8 *data1, const u8 *data2, size_t len,
				 u8 out1[SHA256_DIGEST_SIZE],
				 u8 out2[SHA256_DIGEST_SIZE])
{
	return false;
}
static bool sha256_finup_2x_is_optimized_arch(void)
{
	return false;
}
#endif

/*
 * Second reason this file exists: sha256_finup_2x_arch() is ALSO `static`,
 * unrelated to sha256_blocks() (see the file header comment), so it too
 * needs a symbol.
 */
bool sha256_finup_2x_dispatch(const struct __sha256_ctx *ctx,
			      const u8 *data1, const u8 *data2, size_t len,
			      u8 *out1, u8 *out2)
{
	return sha256_finup_2x_arch(ctx, data1, data2, len, out1, out2);
}

bool sha256_finup_2x_is_optimized_dispatch(void)
{
	return sha256_finup_2x_is_optimized_arch();
}

#endif /* !__DISABLE_EXPORTS */

#ifdef sha256_mod_init_arch
static int __init sha256_mod_init(void)
{
	sha256_mod_init_arch();
	return 0;
}
subsys_initcall(sha256_mod_init);

static void __exit sha256_mod_exit(void)
{
}
module_exit(sha256_mod_exit);
#endif

MODULE_DESCRIPTION("SHA-224, SHA-256, HMAC-SHA224, and HMAC-SHA256 library functions");
MODULE_LICENSE("GPL");
