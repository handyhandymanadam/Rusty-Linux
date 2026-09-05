// SPDX-License-Identifier: 0BSD

//! LZMA2 decoder — the compression layer of the XZ decompressor.
//!
//! Ported from `lib/xz/xz_dec_lzma2.c` (6.18.49), which carries
//! `Authors: Lasse Collin <lasse.collin@tukaani.org>` and
//! `Igor Pavlov <https://7-zip.org/>` and is 0BSD.
//!
//! This is the range decoder, the LZMA symbol decoder, the sliding-window
//! dictionary, and the LZMA2 chunk-header state machine that drives them. Its
//! callers are `xz_dec_stream_rs.rs` (already Rust) and `xz_dec_bcj_rs.rs`
//! (already Rust), plus — under `CONFIG_XZ_DEC_MICROLZMA` — `fs/erofs`.
//!
//! # Shape: two definitions here, five thunks and two allocators in C
//!
//! **`xz_dec_lzma2_run()` and `xz_dec_lzma2_reset()` are defined here, under
//! their own names.** Neither is `EXPORT_SYMBOL`'d — `lib/xz/xz_dec_syms.c`
//! exports only `xz_dec_{init,reset,run,end}` and the four MicroLZMA entry
//! points — so neither carries a MODVERSIONS CRC and GOALS.md §1's
//! entry-thunk constraint does not reach them. This is the `lib/union_find`
//! shape that `xz_dec_bcj_rs.rs` took, not the `lib/bcd` one.
//!
//! **The four MicroLZMA entry points ARE `EXPORT_SYMBOL`'d**
//! (`xz_dec_syms.c:18-21`, under `#ifdef CONFIG_XZ_DEC_MICROLZMA`), so under
//! `CONFIG_GENDWARFKSYMS` their CRCs come from the DWARF of the *definition*
//! and a Rust definition would change them and break module loading — GOALS.md
//! §2 criterion 4. All four stay C thunks; their bodies are the
//! `rust_xz_dec_microlzma_*` functions below. That is GOALS.md §1's first
//! exception, forced rather than chosen.
//!
//! **The allocations stay C.** `kmalloc` is a macro over a `static inline`
//! with no linkable symbol, and since 6.10's allocation profiling `vmalloc` is
//! `alloc_hooks(vmalloc_noprof(...))` (`include/linux/vmalloc.h:147`) — also a
//! macro, also unlinkable. `kfree` and `vfree` are real out-of-line
//! `EXPORT_SYMBOL`s and could be called from here, but their allocating halves
//! cannot be, so the pairs are kept together in C. That is GOALS.md §1's
//! second exception, and it is the same reasoning that kept
//! `xz_dec_bcj_create()` and `xz_dec_init()` in C.
//!
//! **The C never sees this layout.** `struct xz_dec_lzma2` and
//! `struct xz_dec_microlzma` are defined here and nowhere else in the built
//! kernel, so the two cannot drift. The C asks
//! [`rust_xz_dec_lzma2_size`]/`rust_xz_dec_microlzma_size()` how many bytes to
//! allocate and `rust_*_init` to fill the result in. How big a dictionary to
//! `vmalloc()` it already knows: that is the `dict_max`/`dict_size` argument
//! it was passed, and `DEC_IS_PREALLOC`/`DEC_IS_MULTI` are `xz_private.h`
//! macros over `mode`, not over anything in the struct.
//!
//! `lib/xz/xz_dec_lzma2.c` becomes — keeping, exactly as `xz_dec_bcj.c` does,
//! its whole original body behind `#ifdef STATIC` for the pre-boot
//! decompressor that `lib/decompress_unxz.c:242` textually `#include`s and
//! that has no Rust runtime:
//!
//! ```c
//! /* lib/xz/xz_dec_lzma2_rs.rs */
//! size_t rust_xz_dec_lzma2_size(void);
//! void rust_xz_dec_lzma2_init(void *s, int mode, uint32_t dict_max,
//!                             uint8_t *dict_buf);
//! void *rust_xz_dec_lzma2_dict_to_free(struct xz_dec_lzma2 *s);
//!
//! /* Called FROM the Rust: vmalloc() is a macro over alloc_hooks(), so the
//!  * call site has to be here. vfree() is a plain EXPORT_SYMBOL and the Rust
//!  * calls it directly. */
//! void *xz_dec_lzma2_dict_alloc(uint32_t size)
//! {
//!         return vmalloc(size);
//! }
//!
//! struct xz_dec_lzma2 *xz_dec_lzma2_create(enum xz_mode mode,
//!                                          uint32_t dict_max)
//! {
//!         uint8_t *buf = NULL;
//!         void *s = kmalloc(rust_xz_dec_lzma2_size(), GFP_KERNEL);
//!
//!         if (s == NULL)
//!                 return NULL;
//!
//!         if (DEC_IS_PREALLOC(mode)) {
//!                 buf = vmalloc(dict_max);
//!                 if (buf == NULL) {
//!                         kfree(s);
//!                         return NULL;
//!                 }
//!         }
//!
//!         rust_xz_dec_lzma2_init(s, mode, dict_max, buf);
//!         return s;
//! }
//!
//! void xz_dec_lzma2_end(struct xz_dec_lzma2 *s)
//! {
//!         vfree(rust_xz_dec_lzma2_dict_to_free(s));
//!         kfree(s);
//! }
//!
//! #ifdef CONFIG_XZ_DEC_MICROLZMA
//! /* Four EXPORT_SYMBOL'd entry points: four thunks. */
//! enum xz_ret xz_dec_microlzma_run(struct xz_dec_microlzma *s,
//!                                  struct xz_buf *b)
//! {
//!         return xz_dec_microlzma_run(s, b);
//! }
//!
//! void xz_dec_microlzma_reset(struct xz_dec_microlzma *s, uint32_t comp_size,
//!                             uint32_t uncomp_size, int uncomp_size_is_exact)
//! {
//!         xz_dec_microlzma_reset(s, comp_size, uncomp_size,
//!                                     uncomp_size_is_exact);
//! }
//!
//! struct xz_dec_microlzma *xz_dec_microlzma_alloc(enum xz_mode mode,
//!                                                 uint32_t dict_size)
//! {
//!         uint8_t *buf = NULL;
//!         void *s;
//!
//!         if (!rust_xz_dec_microlzma_dict_size_valid(dict_size))
//!                 return NULL;
//!
//!         s = kmalloc(rust_xz_dec_microlzma_size(), GFP_KERNEL);
//!         if (s == NULL)
//!                 return NULL;
//!
//!         if (DEC_IS_MULTI(mode)) {
//!                 buf = vmalloc(dict_size);
//!                 if (buf == NULL) {
//!                         kfree(s);
//!                         return NULL;
//!                 }
//!         }
//!
//!         rust_xz_dec_microlzma_init(s, mode, dict_size, buf);
//!         return s;
//! }
//!
//! void xz_dec_microlzma_end(struct xz_dec_microlzma *s)
//! {
//!         vfree(rust_xz_dec_microlzma_dict_to_free(s));
//!         kfree(s);
//! }
//! #endif
//! ```
//!
//! `vfree(NULL)` is a documented no-op (`mm/vmalloc.c`: `if (!addr) return;`),
//! which is what lets the two `_end` bodies drop the C's
//! `if (DEC_IS_MULTI(s->dict.mode))` guard: the accessor returns null in
//! exactly the cases where the C would not have called `vfree()` at all. See
//! divergence 7.
//!
//! # `CONFIG_XZ_DEC_MICROLZMA` is real, and both arms must build
//!
//! Unlike `bcj_ia64`, this one has a Kconfig stanza (`lib/xz/Kconfig:48`,
//! `default n`) and `fs/erofs/Kconfig:15` selects it. It is ported, gated on
//! `#[cfg(CONFIG_XZ_DEC_MICROLZMA)]`, and both this project's configs have it
//! **off** — so the gated arm is compiled by the config sweep and by nothing
//! else, and is executed by no test here. **That is a real coverage hole and
//! it is recorded rather than papered over.**
//!
//! Per floor.md's RAISE 1 the *constants* are gated too, not just the uses:
//! `struct XzDecMicrolzma`, `pedantic_microlzma` and the five
//! `rust_xz_dec_microlzma_*` symbols are all behind the same `#[cfg]`, because
//! an item defined ungated whose only use is gated becomes
//! `never used` and `CONFIG_WERROR=y` makes that a build failure.
//! [`DICT_FLUSH_SUPPORTS_SKIPPING`] is the one thing defined *both* ways,
//! because the C defines it both ways and uses it unconditionally.
//!
//! # Deliberate divergences, recorded so nobody fixes them back
//!
//! 1. **The range decoder's input buffer is a parameter, not a field.**
//!    `struct rc_dec` has `const uint8_t *in` pointing at either `s->temp.buf`
//!    or the caller's `b->in`; [`RcDec`] drops that field and every `rc_*`
//!    function takes an [`RcInput`] argument instead. `in_pos` and `in_limit`
//!    stay fields, because `lzma2_lzma()` reads `s->rc.in_pos` back after
//!    `lzma_main()` returns. A `*const u8` field pointing into the same
//!    allocation as the struct that holds it is a self-referential struct, and
//!    keeping it would have meant a raw pointer whose provenance is
//!    invalidated by every `&mut` to `s.temp`. Nothing observes the
//!    difference: the C never reads `rc.in` across a call either.
//!
//! 2. **The single flat `PROBS_TOTAL` loop becomes one assignment per array.**
//!    `lzma_reset()` does `probs = s->lzma.is_match[0];` and then writes
//!    `probs[0 .. PROBS_TOTAL]` — a walk off the end of `is_match` across
//!    eleven more members, which is already out-of-bounds in C and cannot be
//!    written in Rust at all. [`LzmaDec::fill_probs`] assigns each array
//!    instead. A `const` assert checks that the element counts still sum to
//!    [`PROBS_TOTAL`], so if a future array is added or resized the build
//!    fails rather than silently initialising less than the C did. All the
//!    members are `u16` arrays, so C's layout has no padding between them and
//!    the two writes cover exactly the same bytes.
//!
//! 3. **Bounds checks are real.** The dictionary, the caller's `b->in`, and
//!    `temp.buf` are all indexed with offsets the C has reasoned safe.
//!    [`Dictionary::byte_at`], [`Dictionary::store_byte`], [`RcInput::byte`]
//!    and [`in_byte`] check, so a mistranscribed bound is a panic at the wrong
//!    access rather than a read or write past the buffer. The index arithmetic
//!    is transcribed one for one; only the checking is added, and none of the
//!    checks fires on a well-formed call — **including on corrupt input, which
//!    is the whole job of this file.** The one that matters is
//!    [`Dictionary::byte_at`]: `dict_get()` and `dict_repeat()` read
//!    *backwards* by a distance that came straight out of the compressed
//!    stream, and the C's only guard is `dist >= dict->full` in
//!    `dict_repeat()`. Those two check against [`Dictionary::alloc_len`],
//!    which is a field the C does not have; the reason it has to exist is
//!    divergence 10, and getting that wrong is how the first draft of this
//!    file turned a supported MicroLZMA call sequence into a panic.
//!    The cost is a compare-and-branch per byte in
//!    [`dict_repeat`]'s copy loop, which is the file's hottest loop.
//!    **That cost is unmeasured here** — `rig/perf/` is the instrument and it
//!    has not been pointed at this file.
//!
//! 4. **`rust_xz_dec_lzma2_init` and `rust_xz_dec_microlzma_init` write every
//!    field.** `xz_dec_lzma2_create()` sets only `dict.mode`, `dict.size_max`
//!    and (in two of three modes) `dict.buf`/`dict.allocated`;
//!    `xz_dec_microlzma_alloc()` sets only `dict.mode`, `dict.size` and — in
//!    multi-call mode — `dict.end`/`dict.buf`. Everything else is left
//!    uninitialised until `xz_dec_lzma2_reset()`, `xz_dec_microlzma_reset()`,
//!    `dict_reset()` or `lzma_props()` happens to store to it. Reading
//!    uninitialised memory is UB in Rust. Nothing outside can observe the
//!    difference, because `xz_private.h` and `include/linux/xz.h` both require
//!    a reset before the first run.
//!
//! 5. **`dict_flush()`'s `b->out == NULL` skip is spelled with a `const bool`,
//!    not an `#ifdef`.** The C's `DICT_FLUSH_SUPPORTS_SKIPPING` is `true` only
//!    under `XZ_DEC_MICROLZMA`; [`DICT_FLUSH_SUPPORTS_SKIPPING`] is defined
//!    both ways here and the `if` is written out unconditionally, exactly as
//!    the C writes it. `&&`/`||` short-circuit on a `const` fold away, so the
//!    generated code is the same in both configurations.
//!
//! 6. **Every place the C relies on unsigned wraparound is spelled
//!    `wrapping_*`, and one of them is a genuine C truncation.** See the
//!    per-site comments; the list is in [`lzma2_lzma`], [`dict_get`],
//!    [`dict_repeat`] and [`rc_direct`]. The sharp ones:
//!
//!    - `s->lzma2.compressed - s->temp.size` and the `compressed -=
//!      s->rc.in_pos` that follows it **can both underflow on corrupt input**,
//!      and I could not establish an invariant that says otherwise; see
//!      [`lzma2_lzma`]'s own docs for the state I traced to reach it.
//!      `uint32_t` wraparound is *defined* in C, so `wrapping_sub` here is
//!      byte-for-byte the C and a plain `-` would be a kernel panic on input
//!      the C decodes (badly, but without faulting).
//!    - `in_avail >= s->lzma2.compressed + LZMA_IN_REQUIRED` computes the
//!      right-hand side in `unsigned int` — `uint32_t + int` is `uint32_t` by
//!      the usual arithmetic conversions — so it **wraps mod 2^32 before**
//!      being widened to `size_t` for the comparison. Reproduced as
//!      `u64::from(compressed.wrapping_add(LZMA_IN_REQUIRED))`. Only reachable
//!      once `compressed` has been wrapped by the bullet above.
//!    - `dict->pos - dist - 1` underflows by design whenever
//!      `dist >= dict->pos`; the very next line adds `dict->end` back.
//!    - `rc_direct()`'s `mask + 1` where `mask` is `0` or `0xFFFFFFFF`.
//!
//! 7. **`xz_dec_lzma2_end()` and `xz_dec_microlzma_end()` lose their
//!    `if (DEC_IS_MULTI(...))`.** [`rust_xz_dec_lzma2_dict_to_free`] returns
//!    null in single-call mode — where `dict.buf` points into the *caller's*
//!    output buffer and must never be freed — and the C calls `vfree()`
//!    unconditionally on what it gets back. `vfree(NULL)` is a no-op, so the
//!    two programs free exactly the same allocations. The accessor exists so
//!    that the C no longer has to know either the layout or the mode.
//!
//! 8. **`xz_dec_lzma2_reset()`'s `vmalloc()` goes out through a C helper
//!    rather than the function staying C.** It is not a pure allocator like
//!    `xz_dec_lzma2_create()`: it validates the LZMA2 Filter Properties byte,
//!    derives the dictionary size, enforces `dict_max`, and sets up the chunk
//!    state machine, and only the `XZ_DYNALLOC` arm allocates. Splitting the
//!    control flow to put the allocation back on the C side would have meant
//!    two entry points and a redesign of an error path whose ordering *is*
//!    observable (on `XZ_MEM_ERROR` the C leaves `lzma2.sequence`,
//!    `need_dict_reset` and `temp.size` untouched). So the body is transcribed
//!    line for line and the one `vmalloc()` becomes a call to a three-line
//!    `xz_dec_lzma2_dict_alloc()` in `xz_dec_lzma2.c`. **The cost, stated
//!    plainly:** under `CONFIG_MEM_ALLOC_PROFILING=y` the allocation is
//!    attributed to that helper's line rather than to `xz_dec_lzma2_reset()`'s,
//!    because `alloc_hooks()` keys on the call site. Nothing else changes, and
//!    with the profiler off (both of this project's configs) the two are
//!    identical.
//!
//! 9. **`dict_repeat()`'s `do { ... } while (--left > 0)` panics instead of
//!    wrapping if it is ever entered with `left == 0`.** In C that would
//!    decrement to `0xFFFFFFFF` and scribble four billion bytes through the
//!    dictionary. `left` is `min(dict->limit - dict->pos, *len)` and both
//!    call sites test `dict_has_space()` (so `limit - pos >= 1`) and
//!    `*len > 0`, so it cannot be zero; the invariant is asserted rather than
//!    assumed. Note that even without the plain `-=`, the *first* write of a
//!    runaway loop would hit divergence 3's bounds check.
//!
//! 10. **`struct dictionary` gains an `alloc_len` member, because the C's
//!     `end` is two different things and only one of them is a length.**
//!
//!     `dict_reset()` sets `dict.buf = b->out + b->out_pos` **once**, on the
//!     first call, and `dict.pos` counts from there.
//!     `xz_dec_microlzma_run()` then runs, on **every** call
//!     (`xz_dec_lzma2.c:1258-1259`):
//!
//!     ```c
//!     /* This is to allow increasing b->out_size between calls. */
//!     if (DEC_IS_SINGLE(s->dict.mode))
//!             s->dict.end = b->out_size - b->out_pos;
//!     ```
//!
//!     while `dict_flush()` has been advancing `b->out_pos` in step with
//!     `dict.pos`. So from the second call onwards `end` holds
//!     *remaining capacity* — the buffer length **minus `pos`** — and is no
//!     longer a bound for `buf` at all. The C never dereferences through it:
//!     it only computes `end - pos` in `dict_limit()`, where the `size_t`
//!     underflow yields an enormous value, fails the `<=` test, and drops
//!     into the `else` arm that computes the correct absolute
//!     `limit = pos + out_max`. The writes that follow are in bounds of the
//!     real allocation.
//!
//!     **The first draft of this file checked `byte_at`/`store_byte` against
//!     `end` and wrote `dict.end - dict.pos` as a plain `-`. Both fire on
//!     that state**, which `include/linux/xz.h:314-322` documents as
//!     supported usage — "XZ_SINGLE is actually a limited multi-call
//!     mode… one doesn't need to provide space for the whole uncompressed
//!     data on the first call". Any continuation call after more than half
//!     the output buffer has been produced reaches it. That is a panic where
//!     the C decodes correctly, which is a denial of service the port would
//!     have introduced. Found by an adversarial review on 2026-09-04.
//!
//!     `alloc_len` is therefore maintained beside every assignment to `buf`
//!     **and** beside that one assignment to `end`, where it is set to
//!     `b->out_size - b->out_pos + dict.pos` — the true distance from
//!     `dict.buf` to the end of the caller's buffer, which stays correct when
//!     the caller grows `b->out_size`, the thing that C line exists to allow.
//!     `dict_limit()`'s subtraction is `wrapping_sub`.
//!
//!     **Two C defects this port reproduces rather than fixes, on the same
//!     state.** Both are transcribed as they stand.
//!
//!     - `dict_repeat()`'s `if (back == dict->end) back = 0;` also reads
//!       `end` as a ring size, so it wraps `back` to zero hundreds of bytes
//!       early and the C emits **wrong output**. `back` stays below
//!       `limit <= alloc_len` throughout, so the wrap lands in bounds and no
//!       check fires — it is wrong, not unsafe.
//!     - `dict_limit()`'s `<=` arm becomes reachable in that state: with
//!       `L` the true buffer length, `end - pos` is `L - 2 * pos`, which is
//!       `<= out_max` whenever `2 * pos <= L`, so `limit` takes the bogus
//!       `end` and comes out as `L - pos` instead of `pos + out_max`. That is
//!       still `>= pos` and `<= alloc_len`, so again nothing asserts; the
//!       decoder just produces less per call than it meant to. At exactly
//!       `2 * pos == L` it gives `limit == pos` and `dict_has_space()` is
//!       false.
//!
//!       **THIS PARAGRAPH USED TO SAY "IT TERMINATES, AND THE C DOES THE
//!       IDENTICAL THING". THAT WAS FALSE.** An independent adversarial review
//!       on 2026-09-04 refuted it empirically: `xz_dec_microlzma_run()`'s
//!       `while (true)` at `xz_dec_lzma2.c:1262` **spins forever with zero
//!       state change per iteration**, because all three exits fail at once —
//!       `uncompressed != 0`; `b->out_pos != b->out_size` since `pos` stalls
//!       at `end`, which is strictly less than `out_size`; and
//!       `b->in_pos == b->in_size` while `temp.size >= compressed`, all the
//!       remaining input already sitting in `temp.buf`. `lzma_main()` then
//!       decodes nothing and `rc_normalize()` is a no-op, so `rc.in_pos == 0`
//!       and nothing advances.
//!
//!       Reproduced on the pristine C: 2048 bytes of "ABAB…" as a 20-byte
//!       MicroLZMA stream, `XZ_SINGLE`, `out_size = 513` then `1026` — the
//!       second call never returns. **5,713 of 24,000 randomized legal call
//!       sequences hung, every one of them `XZ_SINGLE`, none `XZ_PREALLOC`.**
//!       The trigger is broader than `2 * pos == L`: any continuation call
//!       offering at least as much fresh space as has already been produced,
//!       which includes "double the buffer" and "hand it the whole buffer on
//!       the second call" — the two most natural caller patterns.
//!
//!       **This port hangs identically** (0 divergences over all 24,000
//!       cases), so it is bug-for-bug faithful and NOT a port defect. It is a
//!       liveness bug in the kernel's C: an unkillable loop in kernel context.
//!       Recorded here because the previous wording asserted the opposite and
//!       a reader would have relied on it.
//!
//!     Only `XZ_SINGLE` MicroLZMA reaches any of this. In the XZ path `end`
//!     is written in exactly two places — `dict_reset()`, which zeroes `pos`
//!     in the same breath, and `xz_dec_lzma2_reset()`, which **on success**
//!     sets `need_dict_reset` and so forces a `dict_reset()` before any
//!     decoding. **That is not quite "always", and the first spelling of this
//!     paragraph said it was.** `xz_dec_lzma2_reset()` writes
//!     `end = size` *before* the `XZ_DYNALLOC` allocation and returns
//!     `XZ_MEM_ERROR` *before* setting `need_dict_reset` — the C's ordering,
//!     kept because divergence 8 says it is observable — so a caller that
//!     ignores `XZ_MEM_ERROR` and calls `xz_dec_lzma2_run()` anyway can reach
//!     `SEQ_LZMA_RUN` with `end < pos`. It is harmless: on that path `buf` is
//!     null and `alloc_len` is zero, so [`Dictionary::store_byte`]'s check
//!     fires before any dereference, where the C does a null write. Both are
//!     fatal; this one is cleaner. **That holds for the LZMA path only.** On
//!     the uncompressed-chunk path (control byte `0x02` → `SEQ_COPY` →
//!     [`dict_uncompressed`]) the plain `dict.end - dict.pos` underflows and
//!     panics under `CONFIG_RUST_OVERFLOW_CHECKS=y` (which is `default y`);
//!     with overflow checks off it falls through to an unchecked
//!     `core::ptr::copy` into a null destination, which is UB rather than the
//!     clean panic claimed here. Found by adversarial review 2026-09-04. (`XZ_MEMLIMIT_ERROR` returns before `end`
//!     is written at all, so it does not have this shape.)
//!     Whether upstream should be told is Adam's call, not mine.
//!
//! # What is NOT changed
//!
//! The chunk state machine is transcribed case for case, including the two
//! `fallthrough`s. `SEQ_PROPERTIES -> SEQ_LZMA_PREPARE -> SEQ_LZMA_RUN` is
//! **not** rewritten as `continue`, the way `xz_dec_stream_rs.rs` was able to
//! rewrite its dispatch: the C's `while` condition is
//! `b->in_pos < b->in_size || s->lzma2.sequence == SEQ_LZMA_RUN`, and a
//! fallthrough deliberately skips re-evaluating it. Re-dispatching would turn
//! the `XZ_DATA_ERROR` that `SEQ_LZMA_PREPARE` raises for a chunk whose
//! Compressed Size is below `RC_INIT_BYTES` into an `XZ_OK` whenever the
//! caller's input ran out on exactly that byte. The three cases are one match
//! arm here, with the fallthrough written as two sequential `if`s.
//!
//! Replaces: lib/xz/xz_dec_lzma2.c

use core::ffi::{c_int, c_uchar, c_void};

// ---------------------------------------------------------------------------
// The pieces of the XZ ABI this file touches. `struct xz_buf` is the caller's,
// so GOALS.md §5's layout rule applies: it mirrors include/linux/xz.h exactly.
// `struct xz_dec_lzma2` and `struct xz_dec_microlzma` are ours alone --
// xz_private.h and include/linux/xz.h only forward-declare the tags.
// ---------------------------------------------------------------------------

/// `struct xz_buf`, `include/linux/xz.h`. Owned by the caller of
/// `xz_dec_lzma2_run()`; only `out[out_pos..]`, `in_pos` and `out_pos` may be
/// modified.
#[repr(C)]
pub struct XzBuf {
    /// Beginning of the input buffer. May be null if `in_pos == in_size`.
    pub input: *const c_uchar,
    /// Current position in the input buffer.
    pub in_pos: usize,
    /// Size of the input buffer.
    pub in_size: usize,
    /// Beginning of the output buffer. May be null if `out_pos == out_size`.
    /// With MicroLZMA it may additionally be null to discard output the caller
    /// does not want; see [`DICT_FLUSH_SUPPORTS_SKIPPING`].
    pub out: *mut c_uchar,
    /// Current position in the output buffer.
    pub out_pos: usize,
    /// Size of the output buffer.
    pub out_size: usize,
}

// `enum xz_ret`, include/linux/xz.h. Carried as c_int rather than as a
// `#[repr(C)] enum` for the same reason the two neighbouring ports do it: the
// value crosses the C ABI, and a value outside the enumerators would be
// instant UB in a Rust enum while it is merely a number here. Only the codes
// this file produces are declared -- floor.md RAISE 1: an unused constant is a
// build failure under CONFIG_WERROR=y.
/// `XZ_OK`.
const XZ_OK: c_int = 0;
/// `XZ_STREAM_END`.
const XZ_STREAM_END: c_int = 1;
/// `XZ_MEM_ERROR` — `vmalloc()` of the dictionary failed.
const XZ_MEM_ERROR: c_int = 3;
/// `XZ_MEMLIMIT_ERROR` — the stream asks for a bigger dictionary than
/// `dict_max`.
const XZ_MEMLIMIT_ERROR: c_int = 4;
/// `XZ_OPTIONS_ERROR`.
const XZ_OPTIONS_ERROR: c_int = 6;
/// `XZ_DATA_ERROR`.
const XZ_DATA_ERROR: c_int = 7;

// `enum xz_mode`, include/linux/xz.h. Carried as c_int for the same reason.
// XZ_PREALLOC is deliberately absent, and so is DEC_IS_PREALLOC(): the only
// use of either is in `xz_dec_lzma2_create()`, which stays C. An unused
// constant is a build failure under CONFIG_WERROR=y -- floor.md RAISE 1.
/// `XZ_SINGLE`.
const XZ_SINGLE: c_int = 0;
/// `XZ_DYNALLOC`.
const XZ_DYNALLOC: c_int = 2;

/// `DEC_IS_SINGLE(mode)`, `lib/xz/xz_private.h`.
///
/// The header defines all three of `XZ_DEC_SINGLE`, `XZ_DEC_PREALLOC` and
/// `XZ_DEC_DYNALLOC` in every kernel build — the `#if !defined(...)` block at
/// `xz_private.h:63` fires because nothing in the kernel defines any of them —
/// so all four `DEC_IS_*` macros are the plain comparisons and none of them
/// folds to a constant. Only the pre-boot decompressor narrows the set, and
/// that build uses the retained C.
const fn dec_is_single(mode: c_int) -> bool {
    mode == XZ_SINGLE
}

/// `DEC_IS_DYNALLOC(mode)`, `lib/xz/xz_private.h`.
const fn dec_is_dynalloc(mode: c_int) -> bool {
    mode == XZ_DYNALLOC
}

/// `DEC_IS_MULTI(mode)`, `lib/xz/xz_private.h`.
const fn dec_is_multi(mode: c_int) -> bool {
    mode != XZ_SINGLE
}

// ---------------------------------------------------------------------------
// The C this file calls. Both halves of every allocate/free pair have to live
// on the same side, and the allocating halves are macros with no linkable
// symbol -- see the module docs.
// ---------------------------------------------------------------------------

extern "C" {
    /// `lib/xz/xz_dec_lzma2.c`. Three lines: `return vmalloc(size);`.
    /// `vmalloc` itself is `alloc_hooks(vmalloc_noprof(...))` since 6.10's
    /// allocation profiling and has no linkable symbol. See divergence 8.
    fn xz_dec_lzma2_dict_alloc(size: u32) -> *mut c_uchar;

    /// `mm/vmalloc.c`, `EXPORT_SYMBOL(vfree)` at `:3478`. A real out-of-line
    /// function, unlike its allocating counterpart, so it is called from here
    /// directly. A null argument is a documented no-op.
    fn vfree(addr: *const c_void);
}

// ---------------------------------------------------------------------------
// lib/xz/xz_dec_lzma2.c's own two constants.
// ---------------------------------------------------------------------------

/// `RC_INIT_BYTES`. Range decoder initialisation eats the first five bytes of
/// each LZMA chunk.
const RC_INIT_BYTES: u32 = 5;

/// `LZMA_IN_REQUIRED`. Minimum usable input needed to safely decode one LZMA
/// symbol: the worst case decodes 22 bits using probabilities and 26 direct
/// bits, at most 20 bytes of input, and `lzma_main()` does one extra
/// normalisation before returning, so it is 21 rather than 20.
const LZMA_IN_REQUIRED: u32 = 21;

/// `sizeof(s->temp.buf)` — `3 * LZMA_IN_REQUIRED`.
///
/// The factor of three is load-bearing and is why the assert in
/// [`RcInput::byte`] never fires: `lzma2_lzma()` fills at most
/// `2 * LZMA_IN_REQUIRED` bytes and sets `rc.in_limit` to at most that, and
/// one symbol plus the trailing normalisation reads at most
/// `LZMA_IN_REQUIRED` bytes past `in_limit`.
const TEMP_BUF_SIZE: usize = 3 * LZMA_IN_REQUIRED as usize;

// ---------------------------------------------------------------------------
// lib/xz/xz_lzma2.h. Only the constants this file reads are declared; the
// header also defines RC_TOP_BITS, LEN_SYMBOLS, MATCH_LEN_MAX, ALIGN_MASK,
// FULL_DISTANCES_BITS, LEN_*_BITS, DIST_SLOT_BITS and REPS, none of which
// xz_dec_lzma2.c uses. Declaring them here would be `constant is never used`,
// which CONFIG_WERROR=y turns into a build failure -- floor.md RAISE 1.
// ---------------------------------------------------------------------------

/// `RC_SHIFT_BITS`.
const RC_SHIFT_BITS: u32 = 8;
/// `RC_TOP_VALUE`, `1 << RC_TOP_BITS`.
const RC_TOP_VALUE: u32 = 1 << 24;
/// `RC_BIT_MODEL_TOTAL_BITS`.
const RC_BIT_MODEL_TOTAL_BITS: u32 = 11;
/// `RC_BIT_MODEL_TOTAL`, `1 << RC_BIT_MODEL_TOTAL_BITS`.
const RC_BIT_MODEL_TOTAL: u32 = 1 << RC_BIT_MODEL_TOTAL_BITS;
/// `RC_MOVE_BITS`.
const RC_MOVE_BITS: u32 = 5;

/// `POS_STATES_MAX`, `1 << 4`. A position state is the lowest `pb` bits of the
/// current uncompressed offset.
const POS_STATES_MAX: usize = 1 << 4;

/// `STATES`, the total number of `enum lzma_state` values.
const STATES: usize = 12;

/// `LIT_STATES`. The lowest seven states indicate that the previous symbol was
/// a literal.
const LIT_STATES: u32 = 7;

// `enum lzma_state`, xz_lzma2.h. Carried as a plain u32 rather than a Rust
// enum because `lzma_state_literal()` does arithmetic on it (`*state -= 3`,
// `*state -= 6`), which a Rust enum cannot express without a round trip whose
// failure mode would be UB. Only the seven enumerators this file names are
// declared; the other six are only ever reached by that arithmetic.
/// `STATE_LIT_LIT`, and the state `lzma_reset()` starts from.
const STATE_LIT_LIT: u32 = 0;
/// `STATE_SHORTREP_LIT_LIT`.
const STATE_SHORTREP_LIT_LIT: u32 = 3;
/// `STATE_LIT_MATCH`.
const STATE_LIT_MATCH: u32 = 7;
/// `STATE_LIT_LONGREP`.
const STATE_LIT_LONGREP: u32 = 8;
/// `STATE_LIT_SHORTREP`.
const STATE_LIT_SHORTREP: u32 = 9;
/// `STATE_NONLIT_MATCH`.
const STATE_NONLIT_MATCH: u32 = 10;
/// `STATE_NONLIT_REP`.
const STATE_NONLIT_REP: u32 = 11;

/// `LITERAL_CODER_SIZE`, `0x300`. Each literal coder has three sections:
/// `0x001-0x0FF` without a match byte, `0x101-0x1FF` with match bit 0, and
/// `0x201-0x2FF` with match bit 1.
const LITERAL_CODER_SIZE: usize = 0x300;

/// `LITERAL_CODERS_MAX`, `1 << 4`.
const LITERAL_CODERS_MAX: usize = 1 << 4;

/// `MATCH_LEN_MIN`. The minimum length of a match is two bytes.
const MATCH_LEN_MIN: u32 = 2;

/// `LEN_LOW_SYMBOLS`, `1 << LEN_LOW_BITS` — match lengths 2-9.
const LEN_LOW_SYMBOLS: usize = 1 << 3;
/// `LEN_MID_SYMBOLS`, `1 << LEN_MID_BITS` — match lengths 10-17.
const LEN_MID_SYMBOLS: usize = 1 << 3;
/// `LEN_HIGH_SYMBOLS`, `1 << LEN_HIGH_BITS` — match lengths 18-273.
const LEN_HIGH_SYMBOLS: usize = 1 << 8;

/// `DIST_STATES`. Match lengths of 2, 3 and 4 each get their own set of
/// distance-slot probabilities; lengths of 5 and above share the fourth.
const DIST_STATES: usize = 4;

/// `DIST_SLOTS`, `1 << DIST_SLOT_BITS`.
const DIST_SLOTS: u32 = 1 << 6;

/// `DIST_MODEL_START`. The first distance slot that needs additional bits.
const DIST_MODEL_START: u32 = 4;

/// `DIST_MODEL_END`. The distance slot value of 14 is for distances 128-191;
/// from there up the middle bits are direct rather than modelled.
const DIST_MODEL_END: u32 = 14;

/// `FULL_DISTANCES`, `1 << FULL_DISTANCES_BITS` — distances up to 127 are
/// fully encoded using probabilities.
const FULL_DISTANCES: u32 = 1 << (DIST_MODEL_END / 2);

/// `ALIGN_BITS`. The four lowest bits of a large match distance.
const ALIGN_BITS: u32 = 4;
/// `ALIGN_SIZE`, `1 << ALIGN_BITS`.
const ALIGN_SIZE: usize = 1 << 4;

/// `PROBS_TOTAL`, the total number of probability variables — the length the C
/// walks from `s->lzma.is_match[0]` in `lzma_reset()`. See divergence 2.
const PROBS_TOTAL: usize = 1846 + LITERAL_CODERS_MAX * LITERAL_CODER_SIZE;

/// `lzma_get_dist_state()`, `xz_lzma2.h`. `len` is at least
/// [`MATCH_LEN_MIN`] at every call site, so the subtraction cannot underflow.
const fn lzma_get_dist_state(len: u32) -> u32 {
    if len < DIST_STATES as u32 + MATCH_LEN_MIN {
        len - MATCH_LEN_MIN
    } else {
        DIST_STATES as u32 - 1
    }
}

/// `lzma_state_literal()`, `xz_lzma2.h`. Indicate that the latest symbol was a
/// literal.
fn lzma_state_literal(state: &mut u32) {
    if *state <= STATE_SHORTREP_LIT_LIT {
        *state = STATE_LIT_LIT;
    } else if *state <= STATE_LIT_SHORTREP {
        *state -= 3;
    } else {
        *state -= 6;
    }
}

/// `lzma_state_match()`, `xz_lzma2.h`.
fn lzma_state_match(state: &mut u32) {
    *state = if *state < LIT_STATES {
        STATE_LIT_MATCH
    } else {
        STATE_NONLIT_MATCH
    };
}

/// `lzma_state_long_rep()`, `xz_lzma2.h`.
fn lzma_state_long_rep(state: &mut u32) {
    *state = if *state < LIT_STATES {
        STATE_LIT_LONGREP
    } else {
        STATE_NONLIT_REP
    };
}

/// `lzma_state_short_rep()`, `xz_lzma2.h`.
fn lzma_state_short_rep(state: &mut u32) {
    *state = if *state < LIT_STATES {
        STATE_LIT_SHORTREP
    } else {
        STATE_NONLIT_REP
    };
}

/// `lzma_state_is_literal()`, `xz_lzma2.h`.
const fn lzma_state_is_literal(state: u32) -> bool {
    state < LIT_STATES
}

// ---------------------------------------------------------------------------
// struct xz_dec_lzma2 and its members. Ours alone; the C sees only a pointer.
// ---------------------------------------------------------------------------

/// `struct dictionary` — the history buffer.
///
/// The C's own invariants, from its comment at `xz_dec_lzma2.c:29`:
///
/// ```text
/// start <= pos <= full <= end
/// pos <= limit <= end
/// ```
///
/// and in multi-call mode additionally `end == size` and `size <= size_max`
/// and `allocated <= size`. Most members are `size_t` to support single-call
/// mode, in which they address the caller's output buffer directly.
///
/// `buf` is the one raw pointer this file cannot get rid of: in multi-call
/// mode it is a `vmalloc()`ation owned by `xz_dec_lzma2_create()` and
/// `xz_dec_lzma2_reset()`, and in single-call mode it points into the caller's
/// `b->out`. [`Dictionary::byte_at`] and [`Dictionary::store_byte`] check the
/// offset against [`Dictionary::alloc_len`] — **not** `end`, which is not
/// always a length; see divergence 10. They are also **not** the only things
/// that dereference `buf`: [`dict_uncompressed`] writes through
/// `buf.wrapping_add(pos)` and [`dict_flush`] reads through
/// `buf.wrapping_add(start)`, both raw copies with no `alloc_len` check. Both
/// are sound for reasons local to them — `dict_uncompressed` is XZ-path-only
/// where `end <= alloc_len`, and `dict_flush`'s copy is multi-call-only with
/// `start + copy_size == pos <= end <= alloc_len` — but the invariant a reader
/// was handed here was not the one the code relies on. Corrected after
/// adversarial review, 2026-09-04.
#[repr(C)]
struct Dictionary {
    /// Beginning of the history buffer. Valid for [`Dictionary::alloc_len`]
    /// bytes — **not** `end`, which stops being a length for this pointer in
    /// MicroLZMA single-call mode (divergence 10). The first `full` have been
    /// written.
    buf: *mut c_uchar,
    /// Old position in `buf`, before decoding more data.
    start: usize,
    /// Position in `buf`.
    pos: usize,
    /// How full the dictionary is. Used to detect corrupt input that would
    /// read beyond the beginning of the uncompressed stream.
    full: usize,
    /// Write limit; `buf[limit]` and later bytes are not written.
    limit: usize,
    /// End of the dictionary buffer. In multi-call mode the same as the
    /// dictionary size; in single-call mode the size of the output buffer.
    end: usize,
    /// Size of the dictionary as specified in the Block Header. Used together
    /// with `full` to detect corrupt input.
    size: u32,
    /// Maximum allowed dictionary size in multi-call mode. Ignored in
    /// single-call mode.
    size_max: u32,
    /// Amount of memory currently allocated for the dictionary. Used only with
    /// `XZ_DYNALLOC`.
    allocated: u32,
    /// Operation mode, one of `enum xz_mode`.
    mode: c_int,
    /// **Not a member of the C's `struct dictionary`.** The number of bytes
    /// actually readable and writable from `buf`, which is what
    /// [`Dictionary::byte_at`] and [`Dictionary::store_byte`] check against.
    ///
    /// `end` cannot serve as that bound, because `xz_dec_microlzma_run()`
    /// overwrites it with something that is not a length; see divergence 10.
    /// It is maintained beside every assignment to `buf`, and beside that one
    /// assignment to `end`.
    alloc_len: usize,
}

impl Dictionary {
    /// `dict->buf[offset]`.
    ///
    /// The offset is checked against [`Dictionary::alloc_len`] — **not**
    /// against `end`, which is not always a length; see divergence 10. Callers
    /// generally also have `offset < full`, so the byte read has been written
    /// since the last `dict_reset()` — with one exception found by adversarial
    /// review on 2026-09-04: [`dict_repeat`]'s overlapping forward copy with
    /// `dist == 0` reads at `back == pos` while `full` still holds its
    /// pre-loop value, since `full` is only updated after the loop. The
    /// conclusion still holds (the byte was written earlier in the same loop);
    /// the stated premise did not:
    ///
    /// - [`dict_get`] returns early when `full == 0`, and otherwise its
    ///   `dist` is either 0 (the byte just before `pos`) or a `rep0` that
    ///   [`dict_repeat`] has already validated as `< full`.
    /// - [`dict_repeat`] rejects `dist >= full` before computing `back`, and
    ///   `back` then walks forward, wrapping at `end`.
    fn byte_at(&self, offset: usize) -> u8 {
        assert!(offset < self.alloc_len);
        // SAFETY: `buf` points at `alloc_len` readable bytes -- either the
        // `vmalloc()`ation the C made for us or the caller's output buffer
        // from `dict_reset()` -- and `offset` was just checked against it.
        // The `wrapping_add` is used rather than `add` so that a null `buf`,
        // which is what `XZ_DYNALLOC` starts with, cannot make the *offset*
        // computation itself undefined; the assert above is what stops the
        // dereference, because `alloc_len` is zero until a buffer exists.
        unsafe { *self.buf.wrapping_add(offset) }
    }

    /// `dict->buf[offset] = byte`.
    fn store_byte(&mut self, offset: usize, byte: u8) {
        assert!(offset < self.alloc_len);
        // SAFETY: as `byte_at`. Every caller has `offset < limit`, because
        // `dict_has_space()` gates the write, and `limit` never exceeds the
        // buffer -- see divergence 10 for the one state in which it exceeds
        // `end`.
        unsafe { self.buf.wrapping_add(offset).write(byte) };
    }
}

/// `struct rc_dec` — the range decoder.
///
/// The C's `const uint8_t *in` is not a field here; see divergence 1.
#[repr(C)]
struct RcDec {
    /// The range decoder's current range.
    range: u32,
    /// The range decoder's current code value.
    code: u32,
    /// Number of initialising bytes remaining to be read by [`rc_read_init`].
    init_bytes_left: u32,
    /// Position in the buffer the decoder is reading from.
    in_pos: usize,
    /// Position past which [`rc_limit_exceeded`] reports that there may not be
    /// enough input left to decode another symbol.
    in_limit: usize,
}

/// The buffer a range decoder call is reading from: either `s->temp.buf` or
/// the caller's `b->in`. The C keeps this in `rc->in`; see divergence 1.
#[derive(Clone, Copy)]
struct RcInput {
    /// Start of the readable region.
    ptr: *const c_uchar,
    /// Number of bytes readable from `ptr`.
    len: usize,
}

impl RcInput {
    /// `rc->in[i]`.
    ///
    /// The check never fires: `lzma2_lzma()` sets `rc.in_limit` so that at
    /// least [`LZMA_IN_REQUIRED`] bytes remain after it, and one iteration of
    /// [`lzma_main`] plus its trailing [`rc_normalize`] reads at most that
    /// many past `in_limit`. In the `temp.buf` case the worst case is
    /// `in_limit == 42` and a final `in_pos` of 63, which is exactly
    /// [`TEMP_BUF_SIZE`].
    fn byte(self, i: usize) -> u8 {
        assert!(i < self.len);
        // SAFETY: the constructor's contract is that `ptr` is valid for `len`
        // bytes, and `i` was just checked against `len`. Both constructors are
        // in `lzma2_lzma()`: one takes `s.temp.buf`, the other the caller's
        // `b->in` with its own `b->in_size`.
        unsafe { *self.ptr.wrapping_add(i) }
    }
}

/// `struct lzma_len_dec` — probabilities for a length decoder.
#[repr(C)]
struct LzmaLenDec {
    /// Probability of the match length being at least 10.
    choice: u16,
    /// Probability of the match length being at least 18.
    choice2: u16,
    /// Probabilities for match lengths 2-9.
    low: [[u16; LEN_LOW_SYMBOLS]; POS_STATES_MAX],
    /// Probabilities for match lengths 10-17.
    mid: [[u16; LEN_MID_SYMBOLS]; POS_STATES_MAX],
    /// Probabilities for match lengths 18-273.
    high: [u16; LEN_HIGH_SYMBOLS],
}

impl LzmaLenDec {
    /// Number of `u16` probabilities in one of these. Part of divergence 2's
    /// compile-time check.
    const COUNT: usize = 2
        + POS_STATES_MAX * LEN_LOW_SYMBOLS
        + POS_STATES_MAX * LEN_MID_SYMBOLS
        + LEN_HIGH_SYMBOLS;

    /// What the C's flat `PROBS_TOTAL` loop leaves in this sub-struct.
    fn fill_probs(&mut self, v: u16) {
        self.choice = v;
        self.choice2 = v;
        for row in &mut self.low {
            row.fill(v);
        }
        for row in &mut self.mid {
            row.fill(v);
        }
        self.high.fill(v);
    }

    /// What `kmalloc()` leaves behind is uninitialised, so
    /// `rust_xz_dec_lzma2_init()` needs a value to write. Zero is not what
    /// `lzma_reset()` writes; nothing reads these before `lzma_props()` has
    /// run. See divergence 4.
    const ZERO: Self = Self {
        choice: 0,
        choice2: 0,
        low: [[0; LEN_LOW_SYMBOLS]; POS_STATES_MAX],
        mid: [[0; LEN_MID_SYMBOLS]; POS_STATES_MAX],
        high: [0; LEN_HIGH_SYMBOLS],
    };
}

/// `struct lzma_dec` — the LZMA symbol decoder's state and probability arrays.
#[repr(C)]
struct LzmaDec {
    /// Distance of the most recent match.
    rep0: u32,
    /// Distance of the second most recent match.
    rep1: u32,
    /// Distance of the third most recent match.
    rep2: u32,
    /// Distance of the fourth most recent match.
    rep3: u32,
    /// Types of the most recently seen LZMA symbols — `enum lzma_state`.
    state: u32,
    /// Length of a match. Updated so that [`dict_repeat`] can be called again
    /// to finish repeating the whole match.
    len: u32,
    /// Number of literal context bits.
    lc: u32,
    /// `(1 << lp) - 1`.
    literal_pos_mask: u32,
    /// `(1 << pb) - 1`.
    pos_mask: u32,
    /// If 1, it is a match; otherwise a single 8-bit literal.
    is_match: [[u16; POS_STATES_MAX]; STATES],
    /// If 1, it is a repeated match; the distance is one of `rep0 .. rep3`.
    is_rep: [u16; STATES],
    /// If 0, the distance of a repeated match is `rep0`.
    is_rep0: [u16; STATES],
    /// If 0, the distance of a repeated match is `rep1`.
    is_rep1: [u16; STATES],
    /// If 0, the distance of a repeated match is `rep2`; otherwise `rep3`.
    is_rep2: [u16; STATES],
    /// If 1, the repeated match has a length of one byte.
    is_rep0_long: [[u16; POS_STATES_MAX]; STATES],
    /// Probability tree for the highest two bits of the match distance.
    dist_slot: [[u16; DIST_SLOTS as usize]; DIST_STATES],
    /// Probability trees for the additional bits of a match distance in
    /// `[4, 127]`.
    dist_special: [u16; (FULL_DISTANCES - DIST_MODEL_END) as usize],
    /// Probability tree for the lowest four bits of a match distance of 128 or
    /// more.
    dist_align: [u16; ALIGN_SIZE],
    /// Length of a normal match.
    match_len_dec: LzmaLenDec,
    /// Length of a repeated match.
    rep_len_dec: LzmaLenDec,
    /// Probabilities of literals.
    literal: [[u16; LITERAL_CODER_SIZE]; LITERAL_CODERS_MAX],
}

// Divergence 2's guard. The C writes PROBS_TOTAL u16s starting from
// `is_match[0]`; `fill_probs()` below writes each array by name. If the two
// ever stop covering the same set, this fails the build rather than silently
// initialising a different number of probabilities than the C did.
const _: () = assert!(
    STATES * POS_STATES_MAX
        + STATES
        + STATES
        + STATES
        + STATES
        + STATES * POS_STATES_MAX
        + DIST_STATES * DIST_SLOTS as usize
        + (FULL_DISTANCES - DIST_MODEL_END) as usize
        + ALIGN_SIZE
        + LzmaLenDec::COUNT
        + LzmaLenDec::COUNT
        + LITERAL_CODERS_MAX * LITERAL_CODER_SIZE
        == PROBS_TOTAL
);

impl LzmaDec {
    /// The body of `lzma_reset()`'s probability loop. See divergence 2.
    fn fill_probs(&mut self, v: u16) {
        for row in &mut self.is_match {
            row.fill(v);
        }
        self.is_rep.fill(v);
        self.is_rep0.fill(v);
        self.is_rep1.fill(v);
        self.is_rep2.fill(v);
        for row in &mut self.is_rep0_long {
            row.fill(v);
        }
        for row in &mut self.dist_slot {
            row.fill(v);
        }
        self.dist_special.fill(v);
        self.dist_align.fill(v);
        self.match_len_dec.fill_probs(v);
        self.rep_len_dec.fill_probs(v);
        for row in &mut self.literal {
            row.fill(v);
        }
    }

    /// A defined starting value for [`rust_xz_dec_lzma2_init`]. The C leaves
    /// all of this uninitialised until `lzma_props()` runs; see divergence 4.
    const ZERO: Self = Self {
        rep0: 0,
        rep1: 0,
        rep2: 0,
        rep3: 0,
        state: STATE_LIT_LIT,
        len: 0,
        lc: 0,
        literal_pos_mask: 0,
        pos_mask: 0,
        is_match: [[0; POS_STATES_MAX]; STATES],
        is_rep: [0; STATES],
        is_rep0: [0; STATES],
        is_rep1: [0; STATES],
        is_rep2: [0; STATES],
        is_rep0_long: [[0; POS_STATES_MAX]; STATES],
        dist_slot: [[0; DIST_SLOTS as usize]; DIST_STATES],
        dist_special: [0; (FULL_DISTANCES - DIST_MODEL_END) as usize],
        dist_align: [0; ALIGN_SIZE],
        match_len_dec: LzmaLenDec::ZERO,
        rep_len_dec: LzmaLenDec::ZERO,
        literal: [[0; LITERAL_CODER_SIZE]; LITERAL_CODERS_MAX],
    };
}

/// `enum lzma2_seq` — position in [`lzma2_run`].
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Sequence {
    /// `SEQ_CONTROL`.
    Control = 0,
    /// `SEQ_UNCOMPRESSED_1`.
    Uncompressed1,
    /// `SEQ_UNCOMPRESSED_2`.
    Uncompressed2,
    /// `SEQ_COMPRESSED_0`.
    Compressed0,
    /// `SEQ_COMPRESSED_1`.
    Compressed1,
    /// `SEQ_PROPERTIES`.
    Properties,
    /// `SEQ_LZMA_PREPARE`.
    LzmaPrepare,
    /// `SEQ_LZMA_RUN`.
    LzmaRun,
    /// `SEQ_COPY`.
    Copy,
}

/// `struct lzma2_dec` — the LZMA2 chunk layer's state.
#[repr(C)]
struct Lzma2Dec {
    /// Position in [`lzma2_run`].
    sequence: Sequence,
    /// Next position after decoding the compressed size of the chunk.
    next_sequence: Sequence,
    /// Uncompressed size of the LZMA chunk, 2 MiB at maximum.
    uncompressed: u32,
    /// Compressed size of an LZMA chunk, or the compressed/uncompressed size
    /// of an uncompressed chunk, 64 KiB at maximum.
    compressed: u32,
    /// True if a dictionary reset is needed. False before the first chunk.
    need_dict_reset: bool,
    /// True if new LZMA properties are needed. False before the first LZMA
    /// chunk.
    need_props: bool,
    /// True if `uncomp_size` given to `xz_dec_microlzma_reset()` was exact, in
    /// which case the end of the stream is validated.
    #[cfg(CONFIG_XZ_DEC_MICROLZMA)]
    pedantic_microlzma: bool,
}

/// The C's anonymous `struct { uint32_t size; uint8_t buf[...]; } temp`.
///
/// Holds a small number of input bytes between decoder calls; see
/// [`lzma2_lzma`].
#[repr(C)]
struct Temp {
    /// How many bytes of `buf` are live.
    size: u32,
    /// The staging bytes.
    buf: [u8; TEMP_BUF_SIZE],
}

/// `struct xz_dec_lzma2`.
///
/// The C's comment says the member order matters on x86 for code size — the
/// first 128 bytes are reachable with shorter instructions — so the order is
/// preserved even though nothing outside this file can see it.
#[repr(C)]
pub struct XzDecLzma2 {
    /// The range decoder.
    rc: RcDec,
    /// The history buffer.
    dict: Dictionary,
    /// The LZMA2 chunk layer.
    lzma2: Lzma2Dec,
    /// The LZMA symbol decoder.
    lzma: LzmaDec,
    /// Input bytes carried across calls.
    temp: Temp,
}

/// `struct xz_dec_microlzma`. A wrapper struct that exists, in the C's own
/// words, "to have a nice struct name in the public API".
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[repr(C)]
pub struct XzDecMicrolzma {
    /// The wrapped LZMA2 decoder.
    s: XzDecLzma2,
}

/// `DICT_FLUSH_SUPPORTS_SKIPPING`, `xz_dec_lzma2.c:425`. See divergence 5.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
const DICT_FLUSH_SUPPORTS_SKIPPING: bool = true;
/// `DICT_FLUSH_SUPPORTS_SKIPPING`, `xz_dec_lzma2.c:427`. See divergence 5.
#[cfg(not(CONFIG_XZ_DEC_MICROLZMA))]
const DICT_FLUSH_SUPPORTS_SKIPPING: bool = false;

/// `b->in[i]`.
///
/// The C indexes `b->in` with `b->in_pos` after establishing
/// `b->in_pos < b->in_size`, either in `xz_dec_lzma2_run()`'s loop condition
/// or in `rc_read_init()`'s own test. That reasoning is transcribed and the
/// check is added on top; see divergence 3.
fn in_byte(b: &XzBuf, i: usize) -> u8 {
    assert!(i < b.in_size);
    // SAFETY: `include/linux/xz.h` requires `in[0 .. in_size]` to be readable,
    // and `i` was just checked against `in_size` -- which also covers the
    // documented case of a null `in` with `in_size == 0`, since no index
    // passes the check then. `wrapping_add` is used rather than `add` so the
    // offset computation is defined even for that null pointer.
    unsafe { *b.input.wrapping_add(i) }
}

// ---------------------------------------------------------------------------
// Dictionary
// ---------------------------------------------------------------------------

/// Reset the dictionary state. When in single-call mode, set up the beginning
/// of the dictionary to point to the actual output buffer.
fn dict_reset(dict: &mut Dictionary, b: &XzBuf) {
    if dec_is_single(dict.mode) {
        // `b->out + b->out_pos`. `wrapping_add` rather than `add` because
        // `include/linux/xz.h` permits a null `out` when `out_pos == out_size`,
        // and `<*mut T>::add` on a null pointer is undefined even for a zero
        // offset. Nothing dereferences the result until `end` is nonzero.
        dict.buf = b.out.wrapping_add(b.out_pos);
        dict.end = b.out_size - b.out_pos;
        // `pos` is zeroed just below, so the buffer runs exactly `end` bytes
        // from the new `buf`.
        dict.alloc_len = dict.end;
    }

    dict.start = 0;
    dict.pos = 0;
    dict.limit = 0;
    dict.full = 0;
}

/// Set the dictionary write limit.
fn dict_limit(dict: &mut Dictionary, out_max: usize) {
    // `end - pos` underflows in the one state divergence 10 describes, and the
    // C relies on that: the wrapped value is enormous, fails the `<=` test,
    // and the `else` arm computes the limit the caller actually wanted. A
    // plain `-` would panic there on a supported API sequence.
    if dict.end.wrapping_sub(dict.pos) <= out_max {
        dict.limit = dict.end;
    } else {
        dict.limit = dict.pos + out_max;
    }
}

/// Return true if at least one byte can be written into the dictionary.
fn dict_has_space(dict: &Dictionary) -> bool {
    dict.pos < dict.limit
}

/// Get a byte from the dictionary at the given distance.
///
/// The distance is assumed to be valid, or — as a special case — zero when the
/// dictionary is still empty. That special case is needed for single-call
/// decoding so that a `'\0'` is not written to the end of the destination
/// buffer.
///
/// `dict->pos - dist - 1` underflows whenever `dist >= dict->pos`, which is
/// the ordinary case for a distance that reaches back around the ring; the
/// next line adds `dict->end` to bring it back into range. The C relies on
/// `size_t` wraparound for exactly this, so both subtractions are spelled
/// `wrapping_sub` — a plain `-` would panic on well-formed input.
fn dict_get(dict: &Dictionary, dist: u32) -> u32 {
    let mut offset = dict.pos.wrapping_sub(dist as usize).wrapping_sub(1);

    if dist as usize >= dict.pos {
        // Cannot itself overflow: `offset` is at most `usize::MAX` and this
        // brings it back below `end`, but the C's `+=` on a wrapped value is
        // modular arithmetic and is spelled as such.
        offset = offset.wrapping_add(dict.end);
    }

    // The C computes `offset` unconditionally and only then decides whether to
    // dereference; transcribed, because with `full == 0` the value of `offset`
    // is meaningless and `dict.buf` may still be null.
    if dict.full > 0 {
        u32::from(dict.byte_at(offset))
    } else {
        0
    }
}

/// Put one byte into the dictionary. It is assumed that there is space for it.
fn dict_put(dict: &mut Dictionary, byte: u8) {
    let pos = dict.pos;
    dict.store_byte(pos, byte);
    dict.pos = pos + 1;

    if dict.full < dict.pos {
        dict.full = dict.pos;
    }
}

/// Repeat a given number of bytes from a given distance.
///
/// If the distance is invalid, false is returned. On success, true is returned
/// and `*len` is updated to indicate how many bytes were left to be repeated.
///
/// `dist` comes straight out of the compressed stream. The two tests below are
/// the only thing standing between it and the dictionary, and they are what
/// makes [`Dictionary::byte_at`]'s reasoning hold: `dist < full <= end` bounds
/// `back` into the buffer whichever side of `pos` it lands on.
fn dict_repeat(dict: &mut Dictionary, len: &mut u32, dist: u32) -> bool {
    if dist as usize >= dict.full || dist >= dict.size {
        return false;
    }

    // `min_t(size_t, dict->limit - dict->pos, *len)` assigned to a uint32_t.
    // The `min` with `*len` bounds the result below 2^32, so the C's implicit
    // narrowing cannot lose anything.
    let mut left = core::cmp::min(dict.limit - dict.pos, *len as usize) as u32;
    *len -= left;

    // As in `dict_get`: this underflows by design when `dist >= pos`, and the
    // next line adds `end` back.
    let mut back = dict.pos.wrapping_sub(dist as usize).wrapping_sub(1);
    if dist as usize >= dict.pos {
        back = back.wrapping_add(dict.end);
    }

    // The C's `do { ... } while (--left > 0)`. `left` is at least one at both
    // call sites -- see divergence 9 -- so the decrement below is a plain `-=`
    // and panics rather than wrapping if that ever stops being true.
    debug_assert!(left > 0);
    loop {
        let byte = dict.byte_at(back);
        let pos = dict.pos;
        dict.store_byte(pos, byte);
        dict.pos = pos + 1;

        back += 1;
        if back == dict.end {
            back = 0;
        }

        left -= 1;
        if left == 0 {
            break;
        }
    }

    if dict.full < dict.pos {
        dict.full = dict.pos;
    }

    true
}

/// Copy uncompressed data as is from the input to the dictionary and output
/// buffers.
fn dict_uncompressed(dict: &mut Dictionary, b: &mut XzBuf, left: &mut u32) {
    while *left > 0 && b.in_pos < b.in_size && b.out_pos < b.out_size {
        let mut copy_size = core::cmp::min(b.in_size - b.in_pos, b.out_size - b.out_pos);
        if copy_size > dict.end - dict.pos {
            copy_size = dict.end - dict.pos;
        }
        if copy_size > *left as usize {
            copy_size = *left as usize;
        }

        *left -= copy_size as u32;

        // If doing in-place decompression in single-call mode and the
        // uncompressed size of the file is larger than the caller thought
        // (i.e. it is invalid input!), the buffers here may overlap and cause
        // undefined behavior with memcpy(). With valid inputs memcpy() would
        // be fine here.
        //
        // SAFETY: `copy_size` was just clamped to `in_size - in_pos`,
        // `out_size - out_pos` and `dict.end - dict.pos`, so both ranges are
        // inside their buffers: the source is `b->in[in_pos .. in_pos +
        // copy_size]`, which `include/linux/xz.h` requires to be readable, and
        // the destination is `dict.buf[pos .. pos + copy_size]`, which is
        // inside the `alloc_len` bytes `Dictionary` promises (NOT `end`; see
        // divergence 10). `copy` is `memmove`,
        // which is what the C uses here and for the same reason: the two may
        // be the same memory.
        unsafe {
            core::ptr::copy(
                b.input.wrapping_add(b.in_pos),
                dict.buf.wrapping_add(dict.pos),
                copy_size,
            );
        }
        dict.pos += copy_size;

        if dict.full < dict.pos {
            dict.full = dict.pos;
        }

        if dec_is_multi(dict.mode) {
            if dict.pos == dict.end {
                dict.pos = 0;
            }

            // Like above but for multi-call mode: use memmove() to avoid
            // undefined behavior with invalid input.
            //
            // SAFETY: as above, on the output side. `copy_size` is at most
            // `out_size - out_pos`.
            unsafe {
                core::ptr::copy(
                    b.input.wrapping_add(b.in_pos),
                    b.out.wrapping_add(b.out_pos),
                    copy_size,
                );
            }
        }

        dict.start = dict.pos;

        b.out_pos += copy_size;
        b.in_pos += copy_size;
    }
}

/// Flush pending data from the dictionary to `b->out`.
///
/// It is assumed that there is enough space in `b->out`; that is guaranteed
/// because the caller uses [`dict_limit`] before decoding data into the
/// dictionary.
///
/// The C returns `uint32_t` while `copy_size` is a `size_t`, so the return
/// value is an implicit narrowing. It cannot lose anything: `pos - start` is
/// bounded by the `out_max` [`dict_limit`] was given, which is itself bounded
/// by `s->lzma2.uncompressed`, a `uint32_t`.
fn dict_flush(dict: &mut Dictionary, b: &mut XzBuf) -> u32 {
    let copy_size = dict.pos - dict.start;

    if dec_is_multi(dict.mode) {
        if dict.pos == dict.end {
            dict.pos = 0;
        }

        // These buffers cannot overlap even if doing in-place decompression,
        // because in multi-call mode dict->buf has been allocated by us in
        // this file; it's not provided by the caller like in single-call mode.
        //
        // With MicroLZMA, b->out can be NULL to skip bytes that the caller
        // doesn't need. This cannot be done with XZ because it would break BCJ
        // filters.
        // `copy_size != 0` is not in the C. It is here because Rust requires
        // both pointers of `copy_nonoverlapping` to be non-null even for a
        // zero count, and `include/linux/xz.h` permits a null `b->out` when
        // `out_pos == out_size` -- in which case `dict_limit()` gives
        // `out_max == 0` and `copy_size` is zero. `memcpy(NULL, p, 0)` is UB
        // by the letter of C too; this is the same program with the corner
        // spelled out.
        if copy_size != 0 && (!DICT_FLUSH_SUPPORTS_SKIPPING || !b.out.is_null()) {
            // SAFETY: `copy_size` is `pos - start` and both are inside the
            // dictionary, so the source is in bounds; the destination is in
            // bounds because `dict_limit()` capped `pos - start` at
            // `b->out_size - b->out_pos` before any of it was decoded. The two
            // do not overlap: `dict.buf` here is the `vmalloc()`ation, since
            // this branch requires multi-call mode.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    dict.buf.wrapping_add(dict.start),
                    b.out.wrapping_add(b.out_pos),
                    copy_size,
                );
            }
        }
    }

    dict.start = dict.pos;
    b.out_pos += copy_size;
    copy_size as u32
}

// ---------------------------------------------------------------------------
// Range decoder
//
// Every one of these is __always_inline in the C and is the hot path. The bit
// arithmetic is transcribed operation for operation.
// ---------------------------------------------------------------------------

/// Reset the range decoder.
fn rc_reset(rc: &mut RcDec) {
    rc.range = u32::MAX;
    rc.code = 0;
    rc.init_bytes_left = RC_INIT_BYTES;
}

/// Read the first five initial bytes into `rc->code` if they haven't been read
/// already. (Yes, the first byte gets completely ignored.)
fn rc_read_init(rc: &mut RcDec, b: &mut XzBuf) -> bool {
    while rc.init_bytes_left > 0 {
        if b.in_pos == b.in_size {
            return false;
        }

        // `(rc->code << 8) + b->in[b->in_pos++]`. The shift discards the top
        // byte of `code` on the fifth iteration, which is exactly why the C
        // says the first byte is ignored; Rust's `<<` on `u32` is defined to
        // discard, and `overflow-checks` does not apply to it. The `+` cannot
        // overflow because the shift leaves the low eight bits zero.
        rc.code = (rc.code << RC_SHIFT_BITS) + u32::from(in_byte(b, b.in_pos));
        b.in_pos += 1;
        rc.init_bytes_left -= 1;
    }

    true
}

/// Return true if there may not be enough input for the next decoding loop.
fn rc_limit_exceeded(rc: &RcDec) -> bool {
    rc.in_pos > rc.in_limit
}

/// Return true if it is possible (from the point of view of the range decoder)
/// that we have reached the end of the LZMA chunk.
fn rc_is_finished(rc: &RcDec) -> bool {
    rc.code == 0
}

/// Read the next input byte if needed.
fn rc_normalize(rc: &mut RcDec, input: RcInput) {
    if rc.range < RC_TOP_VALUE {
        // `range` is below 2^24 in this branch, so nothing is shifted out of
        // it. `code` is a full 32-bit value and the C discards its top byte
        // here on purpose; see `rc_read_init`.
        rc.range <<= RC_SHIFT_BITS;
        rc.code = (rc.code << RC_SHIFT_BITS) + u32::from(input.byte(rc.in_pos));
        rc.in_pos += 1;
    }
}

/// Decode one bit.
///
/// The C notes that splitting this into three functions made GCC 3.x slower
/// and that it must return an `int` rather than a `bool` for the same reason;
/// neither applies to rustc, but the shape is kept and the return value is
/// kept as the 0/1 the C produces so that the call sites read the same.
fn rc_bit(rc: &mut RcDec, input: RcInput, prob: &mut u16) -> u32 {
    rc_normalize(rc, input);

    // `(range >> 11) * prob` is at most `0x1FFFFF * 2047`, which is
    // 4292868097 -- just inside a u32, which is the whole reason
    // RC_BIT_MODEL_TOTAL_BITS is 11 for a 32-bit range. `prob` never reaches
    // RC_BIT_MODEL_TOTAL itself: it starts at RC_BIT_MODEL_TOTAL / 2 and the
    // update below adds `(2048 - prob) >> 5`, which is zero once prob is 2017
    // or above. So the multiply cannot overflow and a plain `*` is right.
    let bound = (rc.range >> RC_BIT_MODEL_TOTAL_BITS) * u32::from(*prob);
    let bit;

    if rc.code < bound {
        rc.range = bound;
        // `*prob <= RC_BIT_MODEL_TOTAL` is an invariant of the probability
        // model: it starts at RC_BIT_MODEL_TOTAL / 2 and each step moves it a
        // 32nd of the way towards a bound it never crosses. So neither this
        // `+` nor the `-` below can wrap a u16, and a plain operator is right.
        *prob += ((RC_BIT_MODEL_TOTAL - u32::from(*prob)) >> RC_MOVE_BITS) as u16;
        bit = 0;
    } else {
        // `bound <= range` because `bound` is `(range >> 11) * prob` and
        // `prob <= 2048`, and `bound <= code` is the branch condition, so
        // neither subtraction can underflow.
        rc.range -= bound;
        rc.code -= bound;
        *prob -= *prob >> RC_MOVE_BITS;
        bit = 1;
    }

    bit
}

/// Decode a bittree starting from the most significant bit.
///
/// `probs` is the C's array base: `probs[symbol]` here is `probs[symbol]`
/// there, and `symbol` runs `1 ..= limit - 1`, so the slice must have at least
/// `limit` elements. Every call site passes an array whose length is exactly
/// `limit`.
fn rc_bittree(rc: &mut RcDec, input: RcInput, probs: &mut [u16], limit: u32) -> u32 {
    let mut symbol: u32 = 1;

    // The C is a do/while on `symbol < limit`.
    loop {
        if rc_bit(rc, input, &mut probs[symbol as usize]) != 0 {
            symbol = (symbol << 1) + 1;
        } else {
            symbol <<= 1;
        }

        if symbol >= limit {
            break;
        }
    }

    symbol
}

/// Decode a bittree starting from the least significant bit.
///
/// **`probs1` is the C's array base plus one**: `probs1[i]` here is the C's
/// `probs[i + 1]`. The offset exists because one call site passes
/// `s->lzma.dist_special + s->lzma.rep0 - dist_slot - 1`, which is
/// `&dist_special[-1]` when `dist_slot == 4` — a pointer before the start of
/// the array that the C only ever indexes from 1. Rust cannot form that
/// slice, and shifting the base by one turns every access into a non-negative
/// index into the real array.
fn rc_bittree_reverse(
    rc: &mut RcDec,
    input: RcInput,
    probs1: &mut [u16],
    dest: &mut u32,
    limit: u32,
) {
    let mut symbol: u32 = 1;
    let mut i: u32 = 0;

    // The C is a do/while on `++i < limit`.
    loop {
        if rc_bit(rc, input, &mut probs1[symbol as usize - 1]) != 0 {
            symbol = (symbol << 1) + 1;
            // `i < limit <= 30` and `*dest` is bounded by the caller's
            // analysis in `lzma_match()`, so this cannot overflow.
            *dest += 1 << i;
        } else {
            symbol <<= 1;
        }

        i += 1;
        if i >= limit {
            break;
        }
    }
}

/// Decode direct bits (fixed fifty-fifty probability).
fn rc_direct(rc: &mut RcDec, input: RcInput, dest: &mut u32, limit: u32) {
    let mut limit = limit;

    // The C is a do/while on `--limit > 0`. `limit` is `(dist_slot >> 1) - 1 -
    // ALIGN_BITS` with `dist_slot >= DIST_MODEL_END == 14`, so it is at least
    // 2 and the decrement cannot wrap.
    debug_assert!(limit > 0);
    loop {
        rc_normalize(rc, input);
        rc.range >>= 1;
        // Deliberate underflow: the C subtracts and then tests the sign bit of
        // the wrapped result to decide which half of the range was taken, and
        // adds the range back when it went negative. All three of these are
        // modular arithmetic in the C and are spelled as such here.
        rc.code = rc.code.wrapping_sub(rc.range);
        let mask = 0u32.wrapping_sub(rc.code >> 31);
        rc.code = rc.code.wrapping_add(rc.range & mask);
        // `mask` is 0 or 0xFFFFFFFF, so `mask + 1` is 1 or 0 -- the decoded
        // bit -- and the wrap is the whole point.
        *dest = (*dest << 1).wrapping_add(mask.wrapping_add(1));

        limit -= 1;
        if limit == 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// LZMA
//
// The C passes `struct xz_dec_lzma2 *s` to all of these and reaches
// `s->rc`, `s->dict` and `s->lzma` through it. Rust will not let one `&mut
// XzDecLzma2` hand out `&mut s.rc` and `&mut s.lzma.is_match[..][..]` at the
// same time, so the members are passed separately. They are disjoint fields,
// so the borrows are exactly the C's aliasing.
// ---------------------------------------------------------------------------

/// Decode a literal (one 8-bit byte).
///
/// `lzma_literal_probs()` is inlined into the top of this: the C splits it out
/// only to return a `uint16_t *`, and returning the coder's *index* instead
/// avoids a borrow of `lzma` that would outlive the `dict_get()` below.
fn lzma_literal(rc: &mut RcDec, input: RcInput, dict: &mut Dictionary, lzma: &mut LzmaDec) {
    // lzma_literal_probs(): `prev_byte >> (8 - lc)` plus
    // `(dict.pos & literal_pos_mask) << lc`. `lc + lp <= 4` is enforced by
    // `lzma_props()`, so the shift counts are 4..=8 and 0..=4 and the sum is
    // below LITERAL_CODERS_MAX.
    let prev_byte = dict_get(dict, 0);
    let low = prev_byte >> (8 - lzma.lc);
    let high = ((dict.pos & lzma.literal_pos_mask as usize) as u32) << lzma.lc;
    let coder = (low + high) as usize;

    // Read out of `lzma` before `probs` borrows it.
    let is_literal = lzma_state_is_literal(lzma.state);
    let rep0 = lzma.rep0;

    let symbol;
    {
        let probs = &mut lzma.literal[coder];

        if is_literal {
            symbol = rc_bittree(rc, input, probs, 0x100);
        } else {
            let mut sym: u32 = 1;
            // `match_byte` is shifted left once per bit, at most eight times,
            // so its nine significant bits never leave a u32.
            let mut match_byte = dict_get(dict, rep0) << 1;
            let mut offset: u32 = 0x100;

            // The C is a do/while on `symbol < 0x100`.
            loop {
                let match_bit = match_byte & offset;
                match_byte <<= 1;
                // `offset + match_bit + sym` is below 0x300: `offset` is
                // 0x100 or 0, `match_bit` is `match_byte & offset`, and `sym`
                // is below 0x100 for as long as the loop runs.
                let i = (offset + match_bit + sym) as usize;

                if rc_bit(rc, input, &mut probs[i]) != 0 {
                    sym = (sym << 1) + 1;
                    offset &= match_bit;
                } else {
                    sym <<= 1;
                    offset &= !match_bit;
                }

                if sym >= 0x100 {
                    break;
                }
            }

            symbol = sym;
        }
    }

    // `(uint8_t)symbol` -- `symbol` is in [0x100, 0x200) and the C keeps only
    // its low byte.
    dict_put(dict, symbol as u8);
    lzma_state_literal(&mut lzma.state);
}

/// Decode the length of the match into `*len`.
fn lzma_len(
    rc: &mut RcDec,
    input: RcInput,
    l: &mut LzmaLenDec,
    len: &mut u32,
    pos_state: u32,
) {
    // The C picks `probs` and `limit` together, then does one bittree walk.
    // Split into the three arms here because each borrows a different member
    // of `l`, and a `&mut [u16]` cannot outlive the `if`/`else` in one binding
    // without naming the longest of them.
    let symbol;
    let limit;

    if rc_bit(rc, input, &mut l.choice) == 0 {
        limit = LEN_LOW_SYMBOLS as u32;
        *len = MATCH_LEN_MIN;
        symbol = rc_bittree(rc, input, &mut l.low[pos_state as usize], limit);
    } else if rc_bit(rc, input, &mut l.choice2) == 0 {
        limit = LEN_MID_SYMBOLS as u32;
        *len = MATCH_LEN_MIN + LEN_LOW_SYMBOLS as u32;
        symbol = rc_bittree(rc, input, &mut l.mid[pos_state as usize], limit);
    } else {
        limit = LEN_HIGH_SYMBOLS as u32;
        *len = MATCH_LEN_MIN + LEN_LOW_SYMBOLS as u32 + LEN_MID_SYMBOLS as u32;
        symbol = rc_bittree(rc, input, &mut l.high, limit);
    }

    // `rc_bittree()` returns a value in [limit, 2 * limit), so the subtraction
    // cannot underflow.
    *len += symbol - limit;
}

/// Decode a match. The distance will be stored in `lzma.rep0`.
fn lzma_match(rc: &mut RcDec, input: RcInput, lzma: &mut LzmaDec, pos_state: u32) {
    lzma_state_match(&mut lzma.state);

    lzma.rep3 = lzma.rep2;
    lzma.rep2 = lzma.rep1;
    lzma.rep1 = lzma.rep0;

    lzma_len(rc, input, &mut lzma.match_len_dec, &mut lzma.len, pos_state);

    let dist_state = lzma_get_dist_state(lzma.len) as usize;
    let dist_slot =
        rc_bittree(rc, input, &mut lzma.dist_slot[dist_state], DIST_SLOTS) - DIST_SLOTS;

    if dist_slot < DIST_MODEL_START {
        lzma.rep0 = dist_slot;
    } else {
        let limit = (dist_slot >> 1) - 1;
        lzma.rep0 = 2 + (dist_slot & 1);

        if dist_slot < DIST_MODEL_END {
            // `limit <= 5` here, so `rep0` stays below 96 and the shift loses
            // nothing.
            lzma.rep0 <<= limit;
            // The C's `s->lzma.dist_special + s->lzma.rep0 - dist_slot - 1`,
            // written as `rc_bittree_reverse`'s base-plus-one slice: the `- 1`
            // is what that function's parameter absorbs. `rep0 - dist_slot` is
            // 0 for dist_slot == 4 and rises to 83 for dist_slot == 13, and
            // the largest index reached from there is 30, so the slice never
            // runs off the 114-element array.
            let start = (lzma.rep0 - dist_slot) as usize;
            rc_bittree_reverse(
                rc,
                input,
                &mut lzma.dist_special[start..],
                &mut lzma.rep0,
                limit,
            );
        } else {
            // `dist_slot <= 63`, so `limit <= 30` and this decodes at most 26
            // direct bits into a `rep0` that starts at 2 or 3: at most
            // 0x0FFFFFFF. The shift by ALIGN_BITS then leaves 0xFFFFFFF0 and
            // the reverse bittree adds at most 15. Nothing overflows.
            rc_direct(rc, input, &mut lzma.rep0, limit - ALIGN_BITS);
            lzma.rep0 <<= ALIGN_BITS;
            // The C passes `s->lzma.dist_align` itself, base offset zero, so
            // the base-plus-one slice is `dist_align[1..]`.
            rc_bittree_reverse(
                rc,
                input,
                &mut lzma.dist_align[1..],
                &mut lzma.rep0,
                ALIGN_BITS,
            );
        }
    }
}

/// Decode a repeated match.
///
/// The distance is one of the four most recently seen matches and is stored in
/// `lzma.rep0`.
fn lzma_rep_match(rc: &mut RcDec, input: RcInput, lzma: &mut LzmaDec, pos_state: u32) {
    // `s->lzma.state` is read fresh at each of the C's four subscripts, but
    // nothing between them writes it -- `lzma_state_short_rep()` and
    // `lzma_state_long_rep()` are both after the last one -- so one read here
    // is the same program.
    let state = lzma.state as usize;

    if rc_bit(rc, input, &mut lzma.is_rep0[state]) == 0 {
        if rc_bit(rc, input, &mut lzma.is_rep0_long[state][pos_state as usize]) == 0 {
            lzma_state_short_rep(&mut lzma.state);
            lzma.len = 1;
            return;
        }
    } else {
        let tmp;

        if rc_bit(rc, input, &mut lzma.is_rep1[state]) == 0 {
            tmp = lzma.rep1;
        } else {
            if rc_bit(rc, input, &mut lzma.is_rep2[state]) == 0 {
                tmp = lzma.rep2;
            } else {
                tmp = lzma.rep3;
                lzma.rep3 = lzma.rep2;
            }

            lzma.rep2 = lzma.rep1;
        }

        lzma.rep1 = lzma.rep0;
        lzma.rep0 = tmp;
    }

    lzma_state_long_rep(&mut lzma.state);
    lzma_len(rc, input, &mut lzma.rep_len_dec, &mut lzma.len, pos_state);
}

/// LZMA decoder core.
fn lzma_main(
    rc: &mut RcDec,
    input: RcInput,
    dict: &mut Dictionary,
    lzma: &mut LzmaDec,
) -> bool {
    // If the dictionary was reached during the previous call, try to finish
    // the possibly pending repeat in the dictionary. The C ignores the return
    // value here, and so does this.
    if dict_has_space(dict) && lzma.len > 0 {
        let rep0 = lzma.rep0;
        dict_repeat(dict, &mut lzma.len, rep0);
    }

    // Decode more LZMA symbols. One iteration may consume up to
    // LZMA_IN_REQUIRED - 1 bytes.
    while dict_has_space(dict) && !rc_limit_exceeded(rc) {
        // `s->dict.pos & s->lzma.pos_mask` is a size_t in the C; `pos_mask` is
        // at most 15, so the low bits are all that survive either way.
        let pos_state = (dict.pos & lzma.pos_mask as usize) as u32;
        let state = lzma.state as usize;

        if rc_bit(rc, input, &mut lzma.is_match[state][pos_state as usize]) == 0 {
            lzma_literal(rc, input, dict, lzma);
        } else {
            if rc_bit(rc, input, &mut lzma.is_rep[state]) != 0 {
                lzma_rep_match(rc, input, lzma, pos_state);
            } else {
                lzma_match(rc, input, lzma, pos_state);
            }

            let rep0 = lzma.rep0;
            if !dict_repeat(dict, &mut lzma.len, rep0) {
                return false;
            }
        }
    }

    // Having the range decoder always normalized when we are outside this
    // function makes it easier to correctly handle end of the chunk.
    rc_normalize(rc, input);

    true
}

/// Reset the LZMA decoder and range decoder state.
///
/// The dictionary is not reset here, because the LZMA state may be reset
/// without resetting the dictionary.
fn lzma_reset(s: &mut XzDecLzma2) {
    s.lzma.state = STATE_LIT_LIT;
    s.lzma.rep0 = 0;
    s.lzma.rep1 = 0;
    s.lzma.rep2 = 0;
    s.lzma.rep3 = 0;
    s.lzma.len = 0;

    // All probabilities are initialized to the same value. This hack makes the
    // code smaller by avoiding a separate loop for each probability array.
    //
    // The C reaches every array through one pointer walked off the end of
    // `is_match`; see divergence 2 for why this writes them by name instead,
    // and for the compile-time check that the two cover the same set.
    s.lzma.fill_probs((RC_BIT_MODEL_TOTAL / 2) as u16);

    rc_reset(&mut s.rc);
}

/// Decode and validate the LZMA properties (lc/lp/pb) and calculate the bit
/// masks from the decoded lp and pb values.
///
/// On success the LZMA decoder state is reset and true is returned.
///
/// The encoding is `(pb * 5 + lp) * 9 + lc`, so the largest valid byte is
/// `(4 * 5 + 4) * 9 + 8 == 224`; the C writes that expression out and it is
/// kept. `pos_mask` and `literal_pos_mask` are used as scratch counters for pb
/// and lp before being turned into masks, which is why the `lc + lp > 4` test
/// reads as `s->lzma.lc + s->lzma.literal_pos_mask > 4`.
fn lzma_props(s: &mut XzDecLzma2, props: u8) -> bool {
    let mut props = props;

    if props > (4 * 5 + 4) * 9 + 8 {
        return false;
    }

    s.lzma.pos_mask = 0;
    while props >= 9 * 5 {
        props -= 9 * 5;
        s.lzma.pos_mask += 1;
    }

    // `pos_mask` counted at most four times (224 / 45 == 4), so the shift is
    // at most 4.
    s.lzma.pos_mask = (1 << s.lzma.pos_mask) - 1;

    s.lzma.literal_pos_mask = 0;
    while props >= 9 {
        props -= 9;
        s.lzma.literal_pos_mask += 1;
    }

    s.lzma.lc = u32::from(props);

    if s.lzma.lc + s.lzma.literal_pos_mask > 4 {
        return false;
    }

    s.lzma.literal_pos_mask = (1 << s.lzma.literal_pos_mask) - 1;

    lzma_reset(s);

    true
}

// ---------------------------------------------------------------------------
// LZMA2
// ---------------------------------------------------------------------------

/// Make the LZMA decoder's "it is safe to read `LZMA_IN_REQUIRED` bytes past
/// `in_limit`" assumption safe.
///
/// As long as there is plenty of input left to be decoded in the current LZMA
/// chunk, we decode directly from the caller-supplied input buffer until there
/// are `LZMA_IN_REQUIRED` bytes left. Those remaining bytes are copied into
/// `s->temp.buf`, which (hopefully) gets filled on the next call to this
/// function. We decode a few bytes from the temporary buffer so that we can
/// continue decoding from the caller-supplied input buffer again.
///
/// # The two subtractions I could not prove safe
///
/// `s->lzma2.compressed - s->temp.size` and the `s->lzma2.compressed -=
/// s->rc.in_pos` below both underflow if `s->temp.size` ever exceeds
/// `s->lzma2.compressed`, and the invariant that would rule that out is *not*
/// established. What I traced:
///
/// - Every ordinary path preserves `temp.size <= compressed`: the clamp on
///   `tmp` keeps `temp.size + tmp <= compressed`, the guard
///   `s->rc.in_pos > s->temp.size + tmp` keeps `in_pos <= compressed`, and
///   the tail block sets `temp.size = min(in_avail, compressed)`.
/// - `xz_dec_lzma2_run()`'s `SEQ_LZMA_RUN` re-enters this function with
///   `compressed == 0` whenever a chunk's Compressed Size runs out before its
///   Uncompressed Size does, which corrupt input can arrange. Its end-of-chunk
///   test checks `compressed`, `lzma.len` and `rc_is_finished()` — **but not
///   `temp.size`** — so a leftover `temp.size > 0` can survive into the next
///   chunk, whose `compressed` is then decremented by `RC_INIT_BYTES` and can
///   be as low as 0.
/// - I did not find a concrete input that reaches it, and I did not prove that
///   none does. **SETTLED 2026-09-04: unreachable, with a proof.** An
///   independent adversarial review showed the posited leftover cannot exist,
///   because `temp.size <= compressed` is preserved on every path — the `tmp`
///   clamp gives `temp.size + tmp <= compressed`; the shared decrement drops
///   both sides by the same `rc.in_pos`; block 2 is only entered with
///   `temp.size == 0`; and the refill sets `temp.size = min(in_avail,
///   compressed)`. So `compressed == 0` FORCES `temp.size == 0`. Entry states
///   are clean too: both reset functions zero `temp.size`, and
///   `SEQ_LZMA_PREPARE` is reachable only via `SEQ_CONTROL`. Checked by
///   instrumenting the pristine C at every entry and exit of `lzma2_lzma()`
///   over 12,000 randomized streams in all five live configurations, with
///   bit-flipped and truncated input: **37,816,150,767 checks, 0 violations.**
///   The `wrapping_sub` stays — it is byte-for-byte the C — but the reachability
///   question is answered, not open.
///
/// `uint32_t` wraparound is *defined* in C, so `wrapping_sub` here is exactly
/// what the C computes on every input, reachable or not. A plain `-` would be
/// a kernel panic inside a decompressor on input the C survives.
fn lzma2_lzma(s: &mut XzDecLzma2, b: &mut XzBuf) -> bool {
    let mut in_avail = b.in_size - b.in_pos;

    if s.temp.size > 0 || s.lzma2.compressed == 0 {
        // `temp.size` is below LZMA_IN_REQUIRED at every entry to this
        // function -- every path that stores it either caps it there or sets
        // it from an `in_avail` that is already below it -- so this cannot
        // underflow.
        let mut tmp = 2 * LZMA_IN_REQUIRED - s.temp.size;
        if tmp > s.lzma2.compressed.wrapping_sub(s.temp.size) {
            tmp = s.lzma2.compressed.wrapping_sub(s.temp.size);
        }
        // The C compares a uint32_t against a size_t, which widens `tmp`; the
        // assignment back narrows it, and cannot lose anything because it only
        // happens when `in_avail` is the smaller of the two.
        if tmp as usize > in_avail {
            tmp = in_avail as u32;
        }

        let ts = s.temp.size as usize;
        let tn = tmp as usize;

        // memcpy(s->temp.buf + s->temp.size, b->in + b->in_pos, tmp).
        // Byte by byte through the checked reader rather than as a block: at
        // most 42 bytes, and it keeps the caller's buffer from being aliased
        // by a `&[u8]` while the dictionary -- which may be the same memory
        // when decompressing in place -- is being written.
        for i in 0..tn {
            s.temp.buf[ts + i] = in_byte(b, b.in_pos + i);
        }

        if s.temp.size + tmp == s.lzma2.compressed {
            s.temp.buf[ts + tn..].fill(0);
            s.rc.in_limit = ts + tn;
        } else if s.temp.size + tmp < LZMA_IN_REQUIRED {
            s.temp.size += tmp;
            b.in_pos += tn;
            return true;
        } else {
            // This branch is exactly `temp.size + tmp >= LZMA_IN_REQUIRED`,
            // so the subtraction cannot underflow.
            s.rc.in_limit = ts + tn - LZMA_IN_REQUIRED as usize;
        }

        s.rc.in_pos = 0;
        let rc_in = RcInput {
            ptr: s.temp.buf.as_ptr(),
            len: TEMP_BUF_SIZE,
        };

        if !lzma_main(&mut s.rc, rc_in, &mut s.dict, &mut s.lzma)
            || s.rc.in_pos > ts + tn
        {
            return false;
        }

        // See this function's docs: underflows only on a path whose
        // reachability is settled: unreachable, proven above. Kept as
        // `wrapping_sub` because that is byte-for-byte what the C does.
        s.lzma2.compressed = s.lzma2.compressed.wrapping_sub(s.rc.in_pos as u32);

        if s.rc.in_pos < s.temp.size as usize {
            s.temp.size -= s.rc.in_pos as u32;
            // memmove(s->temp.buf, s->temp.buf + s->rc.in_pos, s->temp.size)
            // -- with the already-decremented size.
            let n = s.temp.size as usize;
            s.temp.buf.copy_within(s.rc.in_pos..s.rc.in_pos + n, 0);
            return true;
        }

        // The branch above took the `in_pos < temp.size` case, so this cannot
        // underflow.
        b.in_pos += s.rc.in_pos - s.temp.size as usize;
        s.temp.size = 0;
    }

    in_avail = b.in_size - b.in_pos;
    if in_avail >= LZMA_IN_REQUIRED as usize {
        s.rc.in_pos = b.in_pos;

        // `s->lzma2.compressed + LZMA_IN_REQUIRED` is computed in
        // `unsigned int` -- uint32_t plus int is uint32_t under the usual
        // arithmetic conversions -- and only then widened to size_t for the
        // comparison. So it WRAPS at 2^32 before the compare, and that
        // truncation is reproduced here rather than being widened away. It
        // only matters once `compressed` has been wrapped by the subtraction
        // this function's docs describe; on every ordinary path `compressed`
        // is at most 65536.
        if in_avail >= s.lzma2.compressed.wrapping_add(LZMA_IN_REQUIRED) as usize {
            s.rc.in_limit = b.in_pos + s.lzma2.compressed as usize;
        } else {
            // `in_avail >= LZMA_IN_REQUIRED` bounds this from below.
            s.rc.in_limit = b.in_size - LZMA_IN_REQUIRED as usize;
        }

        let rc_in = RcInput {
            ptr: b.input,
            len: b.in_size,
        };

        if !lzma_main(&mut s.rc, rc_in, &mut s.dict, &mut s.lzma) {
            return false;
        }

        in_avail = s.rc.in_pos - b.in_pos;
        if in_avail > s.lzma2.compressed as usize {
            return false;
        }

        // Guarded by the test above.
        s.lzma2.compressed -= in_avail as u32;
        b.in_pos = s.rc.in_pos;
    }

    in_avail = b.in_size - b.in_pos;
    if in_avail < LZMA_IN_REQUIRED as usize {
        if in_avail > s.lzma2.compressed as usize {
            in_avail = s.lzma2.compressed as usize;
        }

        // memcpy(s->temp.buf, b->in + b->in_pos, in_avail). At most 20 bytes;
        // see the copy above for why it is byte by byte.
        for i in 0..in_avail {
            s.temp.buf[i] = in_byte(b, b.in_pos + i);
        }

        s.temp.size = in_avail as u32;
        b.in_pos += in_avail;
    }

    true
}

/// The body of `xz_dec_lzma2_run()`.
///
/// Takes care of the LZMA2 control layer and forwards the job of actual LZMA
/// decoding, or of copying uncompressed chunks, to the functions above.
///
/// The C's `switch` has two `fallthrough`s and they are **not** rewritten as a
/// re-dispatch; see "What is NOT changed" in the module docs. The three cases
/// they chain are one arm here, with the fallthrough written as two sequential
/// `if`s that test the sequence the previous one just stored.
fn lzma2_run(s: &mut XzDecLzma2, b: &mut XzBuf) -> c_int {
    while b.in_pos < b.in_size || s.lzma2.sequence == Sequence::LzmaRun {
        match s.lzma2.sequence {
            Sequence::Control => {
                // LZMA2 control byte
                //
                // Exact values:
                //   0x00   End marker
                //   0x01   Dictionary reset followed by an uncompressed chunk
                //   0x02   Uncompressed chunk (no dictionary reset)
                //
                // Highest three bits (s->control & 0xE0):
                //   0xE0   Dictionary reset, new properties and state reset,
                //          followed by LZMA compressed chunk
                //   0xC0   New properties and state reset, followed by LZMA
                //          compressed chunk (no dictionary reset)
                //   0xA0   State reset using old properties, followed by LZMA
                //          compressed chunk (no dictionary reset)
                //   0x80   LZMA chunk (no dictionary or state reset)
                //
                // For LZMA compressed chunks, the lowest five bits
                // (s->control & 1F) are the highest bits of the uncompressed
                // size (bits 16-20).
                //
                // A new LZMA2 stream must begin with a dictionary reset. The
                // first LZMA chunk must set new properties and reset the LZMA
                // state.
                //
                // Values that don't match anything described above are invalid
                // and we return XZ_DATA_ERROR.
                let tmp = in_byte(b, b.in_pos);
                b.in_pos += 1;

                if tmp == 0x00 {
                    return XZ_STREAM_END;
                }

                if tmp >= 0xE0 || tmp == 0x01 {
                    s.lzma2.need_props = true;
                    s.lzma2.need_dict_reset = false;
                    dict_reset(&mut s.dict, b);
                } else if s.lzma2.need_dict_reset {
                    return XZ_DATA_ERROR;
                }

                if tmp >= 0x80 {
                    s.lzma2.uncompressed = u32::from(tmp & 0x1F) << 16;
                    s.lzma2.sequence = Sequence::Uncompressed1;

                    if tmp >= 0xC0 {
                        // When there are new properties, state reset is done
                        // at SEQ_PROPERTIES.
                        s.lzma2.need_props = false;
                        s.lzma2.next_sequence = Sequence::Properties;
                    } else if s.lzma2.need_props {
                        return XZ_DATA_ERROR;
                    } else {
                        s.lzma2.next_sequence = Sequence::LzmaPrepare;
                        if tmp >= 0xA0 {
                            lzma_reset(s);
                        }
                    }
                } else {
                    if tmp > 0x02 {
                        return XZ_DATA_ERROR;
                    }

                    s.lzma2.sequence = Sequence::Compressed0;
                    s.lzma2.next_sequence = Sequence::Copy;
                }
            }

            Sequence::Uncompressed1 => {
                // At most 0x1F0000 + 0xFF00 + 0x100, so no overflow.
                s.lzma2.uncompressed += u32::from(in_byte(b, b.in_pos)) << 8;
                b.in_pos += 1;
                s.lzma2.sequence = Sequence::Uncompressed2;
            }

            Sequence::Uncompressed2 => {
                s.lzma2.uncompressed += u32::from(in_byte(b, b.in_pos)) + 1;
                b.in_pos += 1;
                s.lzma2.sequence = Sequence::Compressed0;
            }

            Sequence::Compressed0 => {
                // At most 0xFF00 + 0x100 == 0x10000.
                s.lzma2.compressed = u32::from(in_byte(b, b.in_pos)) << 8;
                b.in_pos += 1;
                s.lzma2.sequence = Sequence::Compressed1;
            }

            Sequence::Compressed1 => {
                s.lzma2.compressed += u32::from(in_byte(b, b.in_pos)) + 1;
                b.in_pos += 1;
                s.lzma2.sequence = s.lzma2.next_sequence;
            }

            Sequence::Properties | Sequence::LzmaPrepare | Sequence::LzmaRun => {
                if s.lzma2.sequence == Sequence::Properties {
                    let props = in_byte(b, b.in_pos);
                    b.in_pos += 1;
                    if !lzma_props(s, props) {
                        return XZ_DATA_ERROR;
                    }

                    s.lzma2.sequence = Sequence::LzmaPrepare;
                    // fallthrough
                }

                if s.lzma2.sequence == Sequence::LzmaPrepare {
                    if s.lzma2.compressed < RC_INIT_BYTES {
                        return XZ_DATA_ERROR;
                    }

                    if !rc_read_init(&mut s.rc, b) {
                        return XZ_OK;
                    }

                    s.lzma2.compressed -= RC_INIT_BYTES;
                    s.lzma2.sequence = Sequence::LzmaRun;
                    // fallthrough
                }

                // SEQ_LZMA_RUN.
                //
                // Set dictionary limit to indicate how much we want to be
                // encoded at maximum. Decode new data into the dictionary.
                // Flush the new data from dictionary to b->out. Check if we
                // finished decoding this chunk. In case the dictionary got
                // full but we didn't fill the output buffer yet, we may run
                // this loop multiple times without changing
                // s->lzma2.sequence.
                let out_max = core::cmp::min(
                    b.out_size - b.out_pos,
                    s.lzma2.uncompressed as usize,
                );
                dict_limit(&mut s.dict, out_max);
                if !lzma2_lzma(s, b) {
                    return XZ_DATA_ERROR;
                }

                // `dict_flush()` returns at most the `out_max` above, which is
                // at most `uncompressed`, so this cannot underflow.
                s.lzma2.uncompressed -= dict_flush(&mut s.dict, b);

                if s.lzma2.uncompressed == 0 {
                    if s.lzma2.compressed > 0
                        || s.lzma.len > 0
                        || !rc_is_finished(&s.rc)
                    {
                        return XZ_DATA_ERROR;
                    }

                    rc_reset(&mut s.rc);
                    s.lzma2.sequence = Sequence::Control;
                } else if b.out_pos == b.out_size
                    || (b.in_pos == b.in_size
                        && (s.temp.size as usize) < s.lzma2.compressed as usize)
                {
                    return XZ_OK;
                }
            }

            Sequence::Copy => {
                dict_uncompressed(&mut s.dict, b, &mut s.lzma2.compressed);
                if s.lzma2.compressed > 0 {
                    return XZ_OK;
                }

                s.lzma2.sequence = Sequence::Control;
            }
        }
    }

    XZ_OK
}

// ---------------------------------------------------------------------------
// The C ABI.
//
// xz_dec_lzma2_run() and xz_dec_lzma2_reset() are defined here outright --
// neither is EXPORT_SYMBOL'd, so neither needs a thunk. Everything else in
// this section exists because xz_dec_lzma2.c owns the allocations and this
// file owns the layout.
// ---------------------------------------------------------------------------

/// Decode a raw LZMA2 stream from `b->in` to `b->out`.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_lzma2_create()` and reset by
/// `xz_dec_lzma2_reset()`, and must not be concurrently used elsewhere. `b`
/// must point at a live `struct xz_buf` whose `in[..in_size]` is readable and
/// `out[..out_size]` writable, and `*b` must overlap neither `*s` nor the
/// dictionary. This is the contract `xz_dec_stream.c` and `xz_dec_bcj_rs.rs`
/// already uphold.
///
/// Note that `b->in` and `b->out` *are* permitted to overlap each other: that
/// is in-place decompression, which the C's `dict_uncompressed()` calls out by
/// using `memmove()`. Nothing here forms a Rust reference over either buffer,
/// so the overlap stays a raw-pointer question. See divergence 1.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_lzma2_run(s: *mut XzDecLzma2, b: *mut XzBuf) -> c_int {
    // SAFETY: the caller guarantees `s` and `b` are live, initialised and
    // unaliased for the duration of the call, and that `*b` does not overlap
    // `*s`, so the two `&mut`s cannot alias each other.
    let (s, b) = unsafe { (&mut *s, &mut *b) };
    lzma2_run(s, b)
}

/// Decode the LZMA2 properties (one byte) and reset the decoder.
///
/// Returns `XZ_OK` on success, `XZ_MEMLIMIT_ERROR` if the preallocated
/// dictionary is not big enough, `XZ_MEM_ERROR` if the dynamic allocation
/// failed, and `XZ_OPTIONS_ERROR` if `props` indicates something this decoder
/// does not support.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_lzma2_create()` and not
/// concurrently used elsewhere.
#[no_mangle]
pub unsafe extern "C" fn xz_dec_lzma2_reset(s: *mut XzDecLzma2, props: u8) -> c_int {
    // SAFETY: the caller guarantees `s` is live, initialised by
    // `rust_xz_dec_lzma2_init()` and unaliased for the duration of the call.
    let s = unsafe { &mut *s };

    // This limits dictionary size to 3 GiB to keep parsing simpler.
    if props > 39 {
        return XZ_OPTIONS_ERROR;
    }

    s.dict.size = 2 + u32::from(props & 1);
    // `props <= 39` bounds the shift at 30 and the result at 3 << 30, so
    // nothing is shifted out of the u32.
    s.dict.size <<= u32::from(props >> 1) + 11;

    if dec_is_multi(s.dict.mode) {
        if s.dict.size > s.dict.size_max {
            return XZ_MEMLIMIT_ERROR;
        }

        s.dict.end = s.dict.size as usize;

        if dec_is_dynalloc(s.dict.mode) {
            if s.dict.allocated < s.dict.size {
                s.dict.allocated = s.dict.size;

                // SAFETY: `s.dict.buf` is null or a pointer that a previous
                // call to `xz_dec_lzma2_dict_alloc()` returned and that
                // nothing else holds -- in XZ_DYNALLOC mode nothing else ever
                // writes it, because `dict_reset()`'s assignment is behind
                // `DEC_IS_SINGLE`. `vfree(NULL)` is a documented no-op.
                // `xz_dec_lzma2_dict_alloc()` is `vmalloc()` and returns
                // either null or `s.dict.size` writable bytes; it is called
                // from here rather than inlined because `vmalloc` is a macro
                // with no linkable symbol. See divergence 8.
                let buf = unsafe {
                    vfree(s.dict.buf.cast::<c_void>());
                    xz_dec_lzma2_dict_alloc(s.dict.size)
                };
                s.dict.buf = buf;
                // Only on success, and only here: when `allocated >= size`
                // the buffer is reused and is the LARGER, previously
                // allocated one, so `alloc_len` must not be shrunk to `size`.
                s.dict.alloc_len = if buf.is_null() { 0 } else { s.dict.size as usize };

                if buf.is_null() {
                    s.dict.allocated = 0;
                    return XZ_MEM_ERROR;
                }
            }
        }
    }

    s.lzma2.sequence = Sequence::Control;
    s.lzma2.need_dict_reset = true;

    s.temp.size = 0;

    XZ_OK
}

/// How many bytes `xz_dec_lzma2_create()` must `kmalloc()`.
#[no_mangle]
pub extern "C" fn rust_xz_dec_lzma2_size() -> usize {
    // kmalloc returns memory aligned to at least ARCH_KMALLOC_MINALIGN, which
    // is 8 on every architecture the kernel builds Rust for. Anything stricter
    // would need a different allocator, so refuse at compile time.
    const _: () = assert!(core::mem::align_of::<XzDecLzma2>() <= 8);
    core::mem::size_of::<XzDecLzma2>()
}

/// Initialise a freshly allocated LZMA2 decoder.
///
/// This is the tail of the C's `xz_dec_lzma2_create()`: everything after the
/// `kmalloc()` and the `XZ_PREALLOC` `vmalloc()` have succeeded. `dict_buf` is
/// that `vmalloc()`ation in `XZ_PREALLOC` mode and null otherwise, which is
/// what the C leaves in `dict.buf` for `XZ_DYNALLOC` and — divergence 4 —
/// a defined value where the C leaves `XZ_SINGLE`'s uninitialised.
///
/// # Safety
///
/// `s` must point at `rust_xz_dec_lzma2_size()` writable bytes aligned to at
/// least 8. In `XZ_PREALLOC` mode `dict_buf` must be a live `vmalloc()`ation
/// of at least `dict_max` bytes, owned by this struct until
/// `xz_dec_lzma2_end()` frees it; in the other two modes it must be null.
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_lzma2_init(
    s: *mut XzDecLzma2,
    mode: c_int,
    dict_max: u32,
    dict_buf: *mut c_uchar,
) {
    // SAFETY: the caller guarantees `s` covers a correctly aligned allocation
    // of `rust_xz_dec_lzma2_size()` bytes. `write` does not read the old
    // contents, which are whatever kmalloc() left there.
    unsafe {
        s.write(XzDecLzma2 {
            rc: RcDec {
                range: 0,
                code: 0,
                init_bytes_left: 0,
                in_pos: 0,
                in_limit: 0,
            },
            dict: Dictionary {
                buf: dict_buf,
                start: 0,
                pos: 0,
                full: 0,
                limit: 0,
                end: 0,
                size: 0,
                size_max: dict_max,
                allocated: 0,
                mode,
                // A non-null `dict_buf` is the `XZ_PREALLOC` `vmalloc()` of
                // `dict_max` bytes; in the other two modes it is null and
                // there is nothing to read or write yet.
                alloc_len: if dict_buf.is_null() { 0 } else { dict_max as usize },
            },
            lzma2: Lzma2Dec {
                sequence: Sequence::Control,
                next_sequence: Sequence::Control,
                uncompressed: 0,
                compressed: 0,
                need_dict_reset: true,
                need_props: true,
                #[cfg(CONFIG_XZ_DEC_MICROLZMA)]
                pedantic_microlzma: false,
            },
            lzma: LzmaDec::ZERO,
            temp: Temp {
                size: 0,
                buf: [0; TEMP_BUF_SIZE],
            },
        });
    }
}

/// The dictionary buffer `xz_dec_lzma2_end()` must `vfree()`, or null.
///
/// Null in single-call mode, where `dict.buf` points into the *caller's*
/// output buffer, and in multi-call mode before any dictionary has been
/// allocated. `vfree(NULL)` is a no-op, so calling it unconditionally on what
/// this returns frees exactly what the C's
/// `if (DEC_IS_MULTI(s->dict.mode)) vfree(s->dict.buf);` frees. See
/// divergence 7.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_lzma2_create()`.
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_lzma2_dict_to_free(s: *mut XzDecLzma2) -> *mut c_void {
    // SAFETY: the caller guarantees `s` is live and initialised. Reads two
    // fields.
    let dict = unsafe { &(*s).dict };

    if dec_is_multi(dict.mode) {
        dict.buf.cast::<c_void>()
    } else {
        core::ptr::null_mut()
    }
}

// ---------------------------------------------------------------------------
// MicroLZMA
//
// A header format variant in which the first byte of a raw LZMA stream has
// been replaced with the bitwise negation of the lc/lp/pb properties byte.
// CONFIG_XZ_DEC_MICROLZMA is `default n` in lib/xz/Kconfig and is selected by
// fs/erofs/Kconfig; neither of this project's configs sets it, so everything
// below is compiled by the config sweep and executed by no test here.
//
// All four public entry points are EXPORT_SYMBOL'd in xz_dec_syms.c, so all
// four stay C thunks and these are their bodies.
// ---------------------------------------------------------------------------

/// The body of `xz_dec_microlzma_run()`.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
fn microlzma_run(s: &mut XzDecLzma2, b: &mut XzBuf) -> c_int {
    // sequence is SEQ_PROPERTIES before the first input byte,
    // SEQ_LZMA_PREPARE until a total of five bytes have been read, and
    // SEQ_LZMA_RUN for the rest of the input stream.
    if s.lzma2.sequence != Sequence::LzmaRun {
        if s.lzma2.sequence == Sequence::Properties {
            // One byte is needed for the props.
            if b.in_pos >= b.in_size {
                return XZ_OK;
            }

            // Don't increment b->in_pos here. The same byte is also passed to
            // rc_read_init() which will ignore it.
            //
            // `~b->in[b->in_pos]` in the C is a bitwise NOT on an int-promoted
            // uint8_t, truncated back to uint8_t by the parameter type; `!` on
            // a u8 is the same eight bits.
            let props = !in_byte(b, b.in_pos);
            if !lzma_props(s, props) {
                return XZ_DATA_ERROR;
            }

            s.lzma2.sequence = Sequence::LzmaPrepare;
        }

        // xz_dec_microlzma_reset() doesn't validate the compressed size so we
        // do it here. We have to limit the maximum size to avoid integer
        // overflows in lzma2_lzma(). 3 GiB is a nice round number and much
        // more than users of this code should ever need.
        if s.lzma2.compressed < RC_INIT_BYTES || s.lzma2.compressed > (3u32 << 30) {
            return XZ_DATA_ERROR;
        }

        if !rc_read_init(&mut s.rc, b) {
            return XZ_OK;
        }

        // Guarded by the `< RC_INIT_BYTES` test above.
        s.lzma2.compressed -= RC_INIT_BYTES;
        s.lzma2.sequence = Sequence::LzmaRun;

        dict_reset(&mut s.dict, b);
    }

    // This is to allow increasing b->out_size between calls.
    //
    // THIS LINE IS WHY `alloc_len` EXISTS. `dict.buf` was set once, by the
    // `dict_reset()` above, to `b->out + b->out_pos` as it stood on the first
    // call; `dict.pos` counts from there and `dict_flush()` has been advancing
    // `b->out_pos` in step with it. So on every call after the first this
    // stores `(buffer length) - pos` into `end`, and `end` stops being a
    // length for `buf` at all. See divergence 10.
    if dec_is_single(s.dict.mode) {
        s.dict.end = b.out_size - b.out_pos;
        // The real distance from `dict.buf` to the end of the caller's buffer,
        // which is `pos` bytes more than what went into `end`. This is also
        // correct when the caller has *grown* `b->out_size` between calls,
        // which is the thing the C line above exists to allow.
        s.dict.alloc_len = b.out_size - b.out_pos + s.dict.pos;
    }

    loop {
        let out_max = core::cmp::min(b.out_size - b.out_pos, s.lzma2.uncompressed as usize);
        dict_limit(&mut s.dict, out_max);

        if !lzma2_lzma(s, b) {
            return XZ_DATA_ERROR;
        }

        // As in `lzma2_run()`: bounded by `out_max`, so no underflow.
        s.lzma2.uncompressed -= dict_flush(&mut s.dict, b);

        if s.lzma2.uncompressed == 0 {
            if s.lzma2.pedantic_microlzma
                && (s.lzma2.compressed > 0 || s.lzma.len > 0 || !rc_is_finished(&s.rc))
            {
                return XZ_DATA_ERROR;
            }

            return XZ_STREAM_END;
        }

        if b.out_pos == b.out_size {
            return XZ_OK;
        }

        if b.in_pos == b.in_size && s.temp.size < s.lzma2.compressed {
            return XZ_OK;
        }
    }
}

/// The body of `xz_dec_microlzma_run()`, as the C thunk calls it.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_microlzma_alloc()` and reset by
/// `xz_dec_microlzma_reset()`; `b` must satisfy the same contract as in
/// [`xz_dec_lzma2_run`].
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub unsafe extern "C" fn xz_dec_microlzma_run(
    s: *mut XzDecMicrolzma,
    b: *mut XzBuf,
) -> c_int {
    // SAFETY: as `xz_dec_lzma2_run()`. `XzDecMicrolzma` is a one-member
    // wrapper, so `&mut (*s).s` covers the whole allocation.
    let (s, b) = unsafe { (&mut (*s).s, &mut *b) };
    microlzma_run(s, b)
}

/// The body of `xz_dec_microlzma_reset()`.
///
/// `comp_size` is validated in [`xz_dec_microlzma_run`]; `uncomp_size`
/// can safely be anything.
///
/// `uncomp_size_is_exact` is the C's `int`, and the C assigns it straight to a
/// `bool` member, which is a comparison against zero. Written out here.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_microlzma_alloc()` and not
/// concurrently used elsewhere.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub unsafe extern "C" fn xz_dec_microlzma_reset(
    s: *mut XzDecMicrolzma,
    comp_size: u32,
    uncomp_size: u32,
    uncomp_size_is_exact: c_int,
) {
    // SAFETY: the caller guarantees `s` is live, initialised by
    // `rust_xz_dec_microlzma_init()` and unaliased for the duration of the
    // call.
    let s = unsafe { &mut (*s).s };

    s.lzma2.compressed = comp_size;
    s.lzma2.uncompressed = uncomp_size;
    s.lzma2.pedantic_microlzma = uncomp_size_is_exact != 0;

    s.lzma2.sequence = Sequence::Properties;
    s.temp.size = 0;
}

/// How many bytes `xz_dec_microlzma_alloc()` must `kmalloc()`.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub extern "C" fn rust_xz_dec_microlzma_size() -> usize {
    // As `rust_xz_dec_lzma2_size()`.
    const _: () = assert!(core::mem::align_of::<XzDecMicrolzma>() <= 8);
    core::mem::size_of::<XzDecMicrolzma>()
}

/// `xz_dec_microlzma_alloc()`'s range check on `dict_size`.
///
/// "Restrict dict_size to the same range as in the LZMA2 code" — the lower
/// bound is the smallest dictionary `xz_dec_lzma2_reset()` can derive from a
/// properties byte and the upper bound is the 3 GiB that keeps `lzma2_lzma()`
/// free of integer overflows. The C returns NULL when it fails; this returns
/// false and the thunk returns NULL.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub extern "C" fn rust_xz_dec_microlzma_dict_size_valid(dict_size: u32) -> bool {
    !(dict_size < 4096 || dict_size > (3u32 << 30))
}

/// Initialise a freshly allocated MicroLZMA decoder.
///
/// This is the tail of the C's `xz_dec_microlzma_alloc()`. `dict_buf` is the
/// `vmalloc()`ation in multi-call mode and null in single-call mode, where
/// [`microlzma_run`]'s `dict_reset()` points the dictionary at the caller's
/// output buffer instead. As with [`rust_xz_dec_lzma2_init`], every field is
/// written; see divergence 4.
///
/// # Safety
///
/// `s` must point at `rust_xz_dec_microlzma_size()` writable bytes aligned to
/// at least 8. In multi-call mode `dict_buf` must be a live `vmalloc()`ation
/// of at least `dict_size` bytes, owned by this struct until
/// `xz_dec_microlzma_end()` frees it; in single-call mode it must be null.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_microlzma_init(
    s: *mut XzDecMicrolzma,
    mode: c_int,
    dict_size: u32,
    dict_buf: *mut c_uchar,
) {
    // SAFETY: the caller guarantees `s` covers a correctly aligned allocation
    // of `rust_xz_dec_microlzma_size()` bytes. `dict_size` is passed where
    // `xz_dec_lzma2_create()` passes `dict_max` so that `alloc_len` comes out
    // right; `size_max` is written along with it, which the C leaves
    // uninitialised here and which nothing on the MicroLZMA path reads.
    unsafe { rust_xz_dec_lzma2_init(s.cast::<XzDecLzma2>(), mode, dict_size, dict_buf) };

    // SAFETY: the write above initialised every field of `(*s).s`.
    let s = unsafe { &mut (*s).s };

    // What xz_dec_microlzma_alloc() sets on top of the shared initialisation:
    // the dictionary size comes from the caller rather than from a properties
    // byte, and in multi-call mode it is also the size of the buffer.
    s.dict.size = dict_size;
    if dec_is_multi(mode) {
        s.dict.end = dict_size as usize;
    }

    // xz_dec_microlzma_reset() sets this before the first run, but the C
    // leaves it uninitialised until then and Rust may not.
    s.lzma2.sequence = Sequence::Properties;
}

/// The dictionary buffer `xz_dec_microlzma_end()` must `vfree()`, or null.
/// See [`rust_xz_dec_lzma2_dict_to_free`] and divergence 7.
///
/// # Safety
///
/// `s` must be a pointer returned by `xz_dec_microlzma_alloc()`.
#[cfg(CONFIG_XZ_DEC_MICROLZMA)]
#[no_mangle]
pub unsafe extern "C" fn rust_xz_dec_microlzma_dict_to_free(
    s: *mut XzDecMicrolzma,
) -> *mut c_void {
    // SAFETY: `XzDecMicrolzma` is a one-member wrapper, so its address is the
    // address of the `XzDecLzma2` inside it, and the caller's guarantee is the
    // one that function needs.
    unsafe { rust_xz_dec_lzma2_dict_to_free(s.cast::<XzDecLzma2>()) }
}
