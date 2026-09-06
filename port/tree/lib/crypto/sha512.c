// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SHA-384, SHA-512, HMAC-SHA384, and HMAC-SHA512 library functions
 *
 * WHAT IS LEFT OF THIS FILE, AND WHY IT CANNOT BE DELETED
 *
 * Every exported function is in lib/crypto/sha512_rs.rs. What stays here is
 * the ARCHITECTURE DISPATCH, and it stays for the same three reasons
 * lib/crypto/blake2s.c gives (see that file's own header comment, and
 * logs/c-entry-rule.md, which records this as the pattern for the rest of
 * lib/crypto):
 *
 *   - a static_call, defined and updated inside $(SRCARCH)/sha512.h, patched
 *     at boot to select the SSSE3/AVX/AVX2 core;
 *   - kernel_fpu_begin()/kernel_fpu_end() around the SIMD state;
 *   - asmlinkage calls into the three x86 cores.
 *
 * $(SRCARCH)/sha512.h defines sha512_blocks() as a `static` function on top
 * of those, so it has no symbol for the Rust to call. This file gives it
 * one, in sha512_blocks_dispatch().
 *
 * THE GENERIC COMPRESSION IS STILL REACHED. Each of sha512_blocks_ssse3/avx/
 * avx2 falls back to sha512_blocks_generic() whenever irq_fpu_usable() is
 * false -- hard IRQ context, for one -- so the Rust body below runs on a
 * normal machine, not only on an architecture without these extensions.
 */

#include <crypto/hmac.h>
#include <crypto/sha2.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

/* lib/crypto/sha512_rs.rs. */
void rust_sha512_blocks_generic(struct sha512_block_state *state,
				const u8 *data, size_t nblocks);

/* Forward-declared for the same reason as blake2s_compress_dispatch():
 * config-full's -Wmissing-prototypes is fatal (-Werror) and neither this
 * symbol's only caller (Rust, via FFI) nor its lack of an EXPORT_SYMBOL
 * gives the compiler anything else to infer a prototype from.
 */
void sha512_blocks_dispatch(struct sha512_block_state *state,
			    const u8 *data, size_t nblocks);

/*
 * The name $(SRCARCH)/sha512.h expects to fall back to. A tail call to the
 * Rust body.
 */
static void __maybe_unused
sha512_blocks_generic(struct sha512_block_state *state, const u8 *data,
		      size_t nblocks)
{
	rust_sha512_blocks_generic(state, data, nblocks);
}

#ifdef CONFIG_CRYPTO_LIB_SHA512_ARCH
#include "sha512.h" /* $(SRCARCH)/sha512.h */
#else
#define sha512_blocks sha512_blocks_generic
#endif

/*
 * THE REASON THIS FILE EXISTS. sha512_blocks() is `static` -- either the
 * arch header's static_call dispatcher or the macro above -- so it has no
 * symbol. This is that symbol, for lib/crypto/sha512_rs.rs to call. It is
 * not EXPORT_SYMBOL: nothing outside lib/crypto has ever been able to reach
 * it, and giving it away would widen the ABI the port is supposed to
 * preserve.
 */
void sha512_blocks_dispatch(struct sha512_block_state *state,
			    const u8 *data, size_t nblocks)
{
	sha512_blocks(state, data, nblocks);
}

#ifdef sha512_mod_init_arch
static int __init sha512_mod_init(void)
{
	sha512_mod_init_arch();
	return 0;
}
subsys_initcall(sha512_mod_init);

static void __exit sha512_mod_exit(void)
{
}
module_exit(sha512_mod_exit);
#endif

MODULE_DESCRIPTION("SHA-384, SHA-512, HMAC-SHA384, and HMAC-SHA512 library functions");
MODULE_LICENSE("GPL");
