// SPDX-License-Identifier: GPL-2.0

//! The zlib inflate state machine.
//!
//! Ported from `lib/zlib_inflate/inflate.c` (6.18.49), which carries
//! `Copyright (C) 1995-2005 Mark Adler` and is *"Based on zlib 1.2.3 but
//! modified for the Linux Kernel by Richard Purdie"*.
//!
//! # This closes `lib/zlib_inflate/`
//!
//! `inflate_fast()` and `zlib_inflate_table()` were already Rust. With this
//! file, the only C left in the directory is `inflate_syms.c` (a list of
//! `EXPORT_SYMBOL` lines, not code), `infutil.c` (which `rig/candidates.sh`
//! marks coupled — it `kmalloc`s), and the entry thunks below.
//!
//! # This one keeps its C entry symbols
//!
//! Six of them — `zlib_inflate_workspacesize`, `zlib_inflateReset`,
//! `zlib_inflateInit2`, `zlib_inflate`, `zlib_inflateEnd`,
//! `zlib_inflateIncomp` — are `EXPORT_SYMBOL`'d, so they have MODVERSIONS CRCs
//! and GOALS.md §1's hard constraint binds. The `bcd` shape, not the
//! `union_find` shape its two callees were able to use.
//!
//! **Two of the six stay C outright**, and both are about a layout this crate
//! cannot see:
//!
//! - `zlib_inflate_workspacesize()` is `sizeof(struct inflate_workspace)`. A
//!   compile-time fact about a C type, and under `CONFIG_ZLIB_DFLTCC` it
//!   depends on `PAGE_SIZE`.
//! - `zlib_inflateInit2()` derives `&WS(strm)->inflate_state` and
//!   `&WS(strm)->working_window[0]` from that same struct. It hands both
//!   pointers to [`rust_zlib_inflateInit2`], which does everything else.
//!
//! # THE ONE DELIBERATE BEHAVIOURAL DIVERGENCE — read this before comparing
//!
//! **The `MATCH` state gains upstream zlib's `copy > whave` guard, which the
//! kernel's copy does not have. On a corrupt stream this port returns
//! `Z_DATA_ERROR` where the C reads out of bounds.**
//!
//! `upstream/zlib-inflate-oob/` is this project's own report of that bug, and
//! it is still parked. The mechanism: `DISTEXT` checks
//! `offset > whave + out - left` **once**, but `MATCH` can be re-entered on a
//! later `zlib_inflate()` call, where `out - left` restarts at zero. Then
//! `copy = offset - (out - left)` can exceed `wsize`, and
//! `window + (wsize - copy)` underflows.
//!
//! It is not a choice to diverge so much as a choice about *how*. In C the
//! underflow is undefined behaviour that happens to read wild memory. In Rust
//! there are only three options: reproduce it with raw pointers (undefined
//! behaviour, and the window is a slice here), let it panic (`wsize - copy`
//! under `CONFIG_RUST_OVERFLOW_CHECKS=y` — a kernel BUG on attacker input,
//! which is worse), or add the guard upstream zlib already has. GOALS.md §5's
//! three questions:
//!
//! 1. *Can anything outside observe the difference?* **Yes** — but only on an
//!    input where the C's behaviour is undefined, and only for
//!    `windowBits < 15`. Reproducing undefined behaviour is not preserving
//!    behaviour.
//! 2. *Does it change a layout or interface?* No.
//! 3. *Does it force a matching change anywhere else?* No. The pre-boot C in
//!    `inflate.c`'s `#ifdef STATIC` branch is unchanged and still has the bug.
//!
//! **This is flagged in STATUS.md under "Needs Adam".** It makes the parked
//! report concrete: the kernel now has a fixed decoder and an unfixed one, in
//! the same file.
//!
//! # Other divergences
//!
//! 1. **`zlib_adler32()` is reimplemented here.** It is a `static inline` in
//!    `include/linux/zutil.h`, so there is no symbol to call. Transcribed
//!    including its `NMAX` blocking, and the differential compares it against
//!    the C's directly over millions of buffers rather than only through the
//!    stream check.
//!
//! 2. **The input and output are slices, and the bit reader is a struct.** The
//!    C hides an early return inside `NEEDBITS()`; here every one of those
//!    ~30 sites is a visible `break 'inf_leave`. That is the same code with
//!    the control flow written down.
//!
//! 3. **`have` and `left` are `u32`, matching the C's `unsigned`**, even
//!    though `avail_in`/`avail_out` are `unsigned long`. The C truncates on a
//!    buffer over 4 GiB and so does this. Faithful, not accidental.
//!
//! # What is NOT changed
//!
//! `TYPE` falls through to `TYPEDO` **without setting `state->mode`**, so a
//! `NEEDBITS` return inside `TYPEDO` leaves the mode at `TYPE` and the next
//! call re-enters at the `Z_BLOCK` check — which the function head then skips
//! with `if (state->mode == TYPE) state->mode = TYPEDO`. That is deliberate in
//! the C and it is why those two states share one arm here instead of being
//! written as `mode = TYPEDO; continue`.
//!
//! Replaces: lib/zlib_inflate/inflate.c

#![allow(clippy::too_many_arguments)]

use core::ffi::{c_char, c_int, c_uint, c_ulong, c_void};

include!("inffixed_rs.rs");

// ---------------------------------------------------------------------------
// The ABI. All of it is the caller's, so GOALS.md §5's layout rule applies and
// port/test/zlib_inflate/main.c checks every offset against the real headers.
// ---------------------------------------------------------------------------

/// Mirrors `code` in `lib/zlib_inflate/inftrees.h`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Code {
    /// Operation, extra bits, or table-index bits.
    pub op: u8,
    /// Bits consumed by this part of the code.
    pub bits: u8,
    /// Literal byte, base length/distance, or offset to the next table.
    pub val: u16,
}

/// `ENOUGH`, `lib/zlib_inflate/inftrees.h`.
const ENOUGH: usize = 2048;

/// Mirrors `struct inflate_state` in `lib/zlib_inflate/inflate.h` — **all of
/// it**, unlike `inffast_rs.rs`'s deliberately truncated copy, because this
/// file touches every field.
#[repr(C)]
pub struct InflateState {
    /// Current inflate mode.
    pub mode: c_int,
    /// True if processing the last block.
    pub last: c_int,
    /// Bit 0 zlib, bit 1 gzip.
    pub wrap: c_int,
    /// True if a dictionary was provided.
    pub havedict: c_int,
    /// gzip header method and flags.
    pub flags: c_int,
    /// Maximum distance from the zlib header.
    pub dmax: c_uint,
    /// Protected copy of the check value.
    pub check: c_ulong,
    /// Protected copy of the output count.
    pub total: c_ulong,
    /// Log base 2 of the requested window size.
    pub wbits: c_uint,
    /// Window size, or zero if no window is in use.
    pub wsize: c_uint,
    /// Valid bytes in the window.
    pub whave: c_uint,
    /// Window write index.
    pub write: c_uint,
    /// The sliding window.
    pub window: *mut u8,
    /// Input bit accumulator.
    pub hold: c_ulong,
    /// Number of bits in `hold`.
    pub bits: c_uint,
    /// Literal or length of data to copy.
    pub length: c_uint,
    /// Distance back to copy from.
    pub offset: c_uint,
    /// Extra bits needed.
    pub extra: c_uint,
    /// Starting table for length/literal codes.
    pub lencode: *const Code,
    /// Starting table for distance codes.
    pub distcode: *const Code,
    /// Index bits for `lencode`.
    pub lenbits: c_uint,
    /// Index bits for `distcode`.
    pub distbits: c_uint,
    /// Number of code length code lengths.
    pub ncode: c_uint,
    /// Number of length code lengths.
    pub nlen: c_uint,
    /// Number of distance code lengths.
    pub ndist: c_uint,
    /// Number of code lengths in `lens`.
    pub have: c_uint,
    /// Next available space in `codes`.
    pub next: *mut Code,
    /// Temporary storage for code lengths.
    pub lens: [u16; 320],
    /// Work area for code table building.
    pub work: [u16; 288],
    /// Space for code tables.
    pub codes: [Code; ENOUGH],
}

/// Mirrors `struct z_stream_s` in `include/linux/zlib.h`.
#[repr(C)]
pub struct ZStream {
    /// Next input byte.
    pub next_in: *const u8,
    /// Bytes available at `next_in`.
    pub avail_in: c_ulong,
    /// Total input bytes read so far.
    pub total_in: c_ulong,
    /// Where the next output byte goes.
    pub next_out: *mut u8,
    /// Free space remaining at `next_out`.
    pub avail_out: c_ulong,
    /// Total bytes output so far.
    pub total_out: c_ulong,
    /// Last error message, or null.
    pub msg: *mut c_char,
    /// Decoder state.
    pub state: *mut InflateState,
    /// Memory allocated for this stream.
    pub workspace: *mut c_void,
    /// Best guess at the data type.
    pub data_type: c_int,
    /// Adler-32 of the uncompressed data.
    pub adler: c_ulong,
    /// Reserved.
    pub reserved: c_ulong,
}

// `inflate_mode`, positionally. The enum is plain and unvalued.
/// `HEAD`.
pub const HEAD: c_int = 0;
/// `DICTID`.
pub const DICTID: c_int = 9;
/// `DICT`.
pub const DICT: c_int = 10;
/// `TYPE`.
pub const TYPE: c_int = 11;
/// `TYPEDO`.
pub const TYPEDO: c_int = 12;
/// `STORED`.
pub const STORED: c_int = 13;
/// `COPY`.
pub const COPY: c_int = 14;
/// `TABLE`.
pub const TABLE: c_int = 15;
/// `LENLENS`.
pub const LENLENS: c_int = 16;
/// `CODELENS`.
pub const CODELENS: c_int = 17;
/// `LEN`.
pub const LEN: c_int = 18;
/// `LENEXT`.
pub const LENEXT: c_int = 19;
/// `DIST`.
pub const DIST: c_int = 20;
/// `DISTEXT`.
pub const DISTEXT: c_int = 21;
/// `MATCH`.
pub const MATCH: c_int = 22;
/// `LIT`.
pub const LIT: c_int = 23;
/// `CHECK`.
pub const CHECK: c_int = 24;
/// `DONE`.
pub const DONE: c_int = 26;
/// `BAD`.
pub const BAD: c_int = 27;
/// `MEM`.
pub const MEM: c_int = 28;
/// `SYNC`.
pub const SYNC: c_int = 29;

// Return codes and flush values, `include/linux/zlib.h`.
/// `Z_OK`.
const Z_OK: c_int = 0;
/// `Z_STREAM_END`.
const Z_STREAM_END: c_int = 1;
/// `Z_NEED_DICT`.
const Z_NEED_DICT: c_int = 2;
/// `Z_STREAM_ERROR`.
const Z_STREAM_ERROR: c_int = -2;
/// `Z_DATA_ERROR`.
const Z_DATA_ERROR: c_int = -3;
/// `Z_MEM_ERROR`.
const Z_MEM_ERROR: c_int = -4;
/// `Z_BUF_ERROR`.
const Z_BUF_ERROR: c_int = -5;
/// `Z_PACKET_FLUSH`.
const Z_PACKET_FLUSH: c_int = 2;
/// `Z_FINISH`.
const Z_FINISH: c_int = 5;
/// `Z_BLOCK`.
const Z_BLOCK: c_int = 6;
/// `Z_DEFLATED`.
const Z_DEFLATED: u32 = 8;

/// `MAX_WBITS`, `include/linux/zconf.h`.
const MAX_WBITS: c_int = 15;

// Error strings, byte for byte as the C spells them, NUL included.
/// `"incorrect header check"`.
const MSG_HEADER_CHECK: &[u8] = b"incorrect header check\0";
/// `"unknown compression method"`.
const MSG_UNKNOWN_METHOD: &[u8] = b"unknown compression method\0";
/// `"invalid window size"`.
const MSG_WINDOW_SIZE: &[u8] = b"invalid window size\0";
/// `"invalid block type"`.
const MSG_BLOCK_TYPE: &[u8] = b"invalid block type\0";
/// `"invalid stored block lengths"`.
const MSG_STORED_LENGTHS: &[u8] = b"invalid stored block lengths\0";
/// `"too many length or distance symbols"`.
const MSG_TOO_MANY: &[u8] = b"too many length or distance symbols\0";
/// `"invalid code lengths set"`.
const MSG_CODE_LENGTHS: &[u8] = b"invalid code lengths set\0";
/// `"invalid bit length repeat"`.
const MSG_BIT_LENGTH_REPEAT: &[u8] = b"invalid bit length repeat\0";
/// `"invalid literal/lengths set"`.
const MSG_LITLEN_SET: &[u8] = b"invalid literal/lengths set\0";
/// `"invalid distances set"`.
const MSG_DISTANCES_SET: &[u8] = b"invalid distances set\0";
/// `"invalid literal/length code"`.
const MSG_LITLEN_CODE: &[u8] = b"invalid literal/length code\0";
/// `"invalid distance code"`.
const MSG_DISTANCE_CODE: &[u8] = b"invalid distance code\0";
/// `"invalid distance too far back"`.
const MSG_DIST_TOO_FAR: &[u8] = b"invalid distance too far back\0";
/// `"incorrect data check"`.
const MSG_DATA_CHECK: &[u8] = b"incorrect data check\0";

extern "C" {
    /// `lib/zlib_inflate/inffast_rs.rs`, reached by symbol like the C does.
    fn inflate_fast(strm: *mut ZStream, start: c_uint);
    /// `lib/zlib_inflate/inftrees_rs.rs`.
    fn zlib_inflate_table(
        kind: c_uint,
        lens: *mut u16,
        codes: c_uint,
        table: *mut *mut Code,
        bits: *mut c_uint,
        work: *mut u16,
    ) -> c_int;
}

/// `CODES`, `lib/zlib_inflate/inftrees.h`.
const CODES: c_uint = 0;
/// `LENS`.
const LENS: c_uint = 1;
/// `DISTS`.
const DISTS: c_uint = 2;

// ---------------------------------------------------------------------------
// Adler-32. A `static inline` in include/linux/zutil.h, so there is no symbol
// to call and it has to be here.
// ---------------------------------------------------------------------------

/// `BASE`, the largest prime smaller than 65536.
const ADLER_BASE: u32 = 65521;
/// `NMAX`, the largest n such that `255n(n+1)/2 + (n+1)(BASE-1) <= 2^32-1`.
const ADLER_NMAX: usize = 5552;

/// `zlib_adler32()`, `include/linux/zutil.h`.
///
/// The `buf == NULL` case returns 1, which is how the C spells "give me the
/// initial value"; here that is [`adler32_init`].
pub(crate) fn adler32(adler: c_ulong, buf: &[u8]) -> c_ulong {
    let mut s1 = (adler & 0xffff) as u32;
    let mut s2 = ((adler >> 16) & 0xffff) as u32;
    let mut rest = buf;

    while !rest.is_empty() {
        let k = core::cmp::min(rest.len(), ADLER_NMAX);
        for &b in &rest[..k] {
            s1 += b as u32;
            s2 += s1;
        }
        rest = &rest[k..];
        s1 %= ADLER_BASE;
        s2 %= ADLER_BASE;
    }

    (((s2 as c_ulong) << 16) | s1 as c_ulong) as c_ulong
}

/// `zlib_adler32(0L, NULL, 0)`.
fn adler32_init() -> c_ulong {
    1
}

/// `REVERSE()`, `lib/zlib_inflate/inflate.h`: reverse the bytes of a 32-bit
/// value. The C applies it to an `unsigned long` bit accumulator and keeps
/// only what the shifts and masks leave.
fn reverse(q: c_ulong) -> c_ulong {
    let q = q as u32;
    (((q >> 24) & 0xff) + ((q >> 8) & 0xff00) + ((q & 0xff00) << 8) + ((q & 0xff) << 24))
        as c_ulong
}

// ---------------------------------------------------------------------------
// The bit reader. The C keeps these six in locals and shuffles them with
// LOAD()/RESTORE(); the only change here is that they have a name.
// ---------------------------------------------------------------------------

/// `LOAD()`'s six registers, plus the two slice bases they index.
struct Regs<'a> {
    /// The caller's input buffer, `avail_in` bytes at entry.
    inp: &'a [u8],
    /// How far into `inp` the C's `next` pointer has reached.
    ipos: usize,
    /// The C's `have`: input bytes left. `unsigned`, as in the C.
    have: u32,
    /// The caller's output buffer, `avail_out` bytes at entry.
    outp: &'a mut [u8],
    /// How far into `outp` the C's `put` pointer has reached.
    opos: usize,
    /// The C's `left`: output space left.
    left: u32,
    /// The C's `hold`: input bit accumulator.
    hold: c_ulong,
    /// The C's `bits`: number of bits in `hold`.
    bits: u32,
}

impl Regs<'_> {
    /// `PULLBYTE()`. Returns false where the C does `goto inf_leave`.
    #[inline]
    fn pullbyte(&mut self) -> bool {
        if self.have == 0 {
            return false;
        }
        self.have -= 1;
        self.hold += (self.inp[self.ipos] as c_ulong) << self.bits;
        self.ipos += 1;
        self.bits += 8;
        true
    }

    /// `NEEDBITS(n)`. Returns false where the C does `goto inf_leave`.
    #[inline]
    fn needbits(&mut self, n: u32) -> bool {
        while self.bits < n {
            if !self.pullbyte() {
                return false;
            }
        }
        true
    }

    /// `BITS(n)` — the low `n` bits of the accumulator, `n < 16`.
    #[inline]
    fn peek(&self, n: u32) -> u32 {
        (self.hold as u32) & ((1u32 << n) - 1)
    }

    /// `DROPBITS(n)`.
    #[inline]
    fn drop(&mut self, n: u32) {
        self.hold >>= n;
        self.bits -= n;
    }

    /// `BYTEBITS()` — drop zero to seven bits to reach a byte boundary.
    #[inline]
    fn bytebits(&mut self) {
        self.hold >>= self.bits & 7;
        self.bits -= self.bits & 7;
    }

    /// `INITBITS()`.
    #[inline]
    fn initbits(&mut self) {
        self.hold = 0;
        self.bits = 0;
    }
}

// ---------------------------------------------------------------------------
// The DFLTCC hooks. s390 only -- CONFIG_ZLIB_DFLTCC is `depends on S390` --
// so nothing in this project can build or run them. They are here because
// leaving them out would silently break a supported architecture, which is
// exactly the class of defect logs/floor.md RAISE 1 was written for.
// ---------------------------------------------------------------------------

#[cfg(CONFIG_ZLIB_DFLTCC)]
extern "C" {
    /// `lib/zlib_dfltcc/dfltcc_inflate.c`.
    fn dfltcc_reset_inflate_state(strm: *mut ZStream);
    /// `lib/zlib_dfltcc/dfltcc_inflate.c`.
    fn dfltcc_can_inflate(strm: *mut ZStream) -> c_int;
    /// `lib/zlib_dfltcc/dfltcc_inflate.c`.
    fn dfltcc_inflate(strm: *mut ZStream, flush: c_int, ret: *mut c_int) -> c_int;
}

/// `DFLTCC_INFLATE_CONTINUE`.
#[cfg(CONFIG_ZLIB_DFLTCC)]
const DFLTCC_INFLATE_CONTINUE: c_int = 0;
/// `DFLTCC_INFLATE_BREAK`.
#[cfg(CONFIG_ZLIB_DFLTCC)]
const DFLTCC_INFLATE_BREAK: c_int = 1;

/// `INFLATE_RESET_HOOK(strm)`.
///
/// # Safety
/// `strm` must be a live `struct z_stream_s` with its workspace set up.
#[inline]
unsafe fn inflate_reset_hook(strm: *mut ZStream) {
    #[cfg(CONFIG_ZLIB_DFLTCC)]
    // SAFETY: the caller's contract.
    unsafe {
        dfltcc_reset_inflate_state(strm)
    };
    #[cfg(not(CONFIG_ZLIB_DFLTCC))]
    let _ = strm;
}

/// `INFLATE_NEED_UPDATEWINDOW(strm)` and `INFLATE_NEED_CHECKSUM(strm)`, which
/// are the same expression in `dfltcc_inflate.h`.
///
/// # Safety
/// `strm` must be live.
#[inline]
unsafe fn inflate_need_software(strm: *mut ZStream) -> bool {
    #[cfg(CONFIG_ZLIB_DFLTCC)]
    // SAFETY: the caller's contract.
    return unsafe { dfltcc_can_inflate(strm) == 0 };
    #[cfg(not(CONFIG_ZLIB_DFLTCC))]
    {
        let _ = strm;
        true
    }
}

// ---------------------------------------------------------------------------
// Entry points. The C thunks in inflate.c call these.
// ---------------------------------------------------------------------------

/// `zlib_inflateReset()`.
///
/// # Safety
///
/// `strm` may be null; if it is not, `strm->state` may be null. Otherwise both
/// must be live and `state->wbits` must already be set.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_inflateReset(strm: *mut ZStream) -> c_int {
    if strm.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: `strm` is live per the contract above.
    let s = unsafe { &mut *strm };
    if s.state.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: as above.
    let state = unsafe { &mut *s.state };

    s.total_in = 0;
    s.total_out = 0;
    state.total = 0;
    s.msg = core::ptr::null_mut();
    /* to support ill-conceived Java test suite */
    s.adler = 1;
    state.mode = HEAD;
    state.last = 0;
    state.havedict = 0;
    state.dmax = 32768;
    state.hold = 0;
    state.bits = 0;
    state.next = state.codes.as_mut_ptr();
    state.lencode = state.next;
    state.distcode = state.next;

    /* Initialise Window */
    state.wsize = 1u32 << state.wbits;
    state.write = 0;
    state.whave = 0;

    // SAFETY: `strm` is live.
    unsafe { inflate_reset_hook(strm) };
    Z_OK
}

/// `zlib_inflateInit2()`, less the two pointers only the C can compute.
///
/// `state` is `&WS(strm)->inflate_state` and `window` is
/// `&WS(strm)->working_window[0]` — under `CONFIG_ZLIB_DFLTCC` the latter is
/// page-aligned inside an over-allocated buffer. `struct inflate_workspace` is
/// not mirrored in this crate for exactly that reason.
///
/// # Safety
///
/// `strm` may be null. Otherwise `state` must point at a writable
/// `struct inflate_state` and `window` at `1 << MAX_WBITS` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_inflateInit2(
    strm: *mut ZStream,
    state: *mut InflateState,
    window: *mut u8,
    window_bits: c_int,
) -> c_int {
    if strm.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: `strm` is live per the contract above.
    let s = unsafe { &mut *strm };
    /* in case we return an error */
    s.msg = core::ptr::null_mut();
    s.state = state;

    // SAFETY: `state` is live per the contract above.
    let st = unsafe { &mut *state };

    let mut wb = window_bits;
    if wb < 0 {
        st.wrap = 0;
        wb = -wb;
    } else {
        st.wrap = (wb >> 4) + 1;
    }
    if !(8..=MAX_WBITS).contains(&wb) {
        return Z_STREAM_ERROR;
    }
    st.wbits = wb as c_uint;
    st.window = window;

    // SAFETY: `strm` and its state are live.
    unsafe { rust_zlib_inflateReset(strm) }
}

/// `zlib_inflateEnd()`.
///
/// # Safety
/// `strm` may be null.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_inflateEnd(strm: *mut ZStream) -> c_int {
    if strm.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: `strm` is live per the contract above.
    if unsafe { (*strm).state }.is_null() {
        return Z_STREAM_ERROR;
    }
    Z_OK
}

/// `zlib_fixedtables()`.
fn fixedtables(state: &mut InflateState) {
    state.lencode = LENFIX.as_ptr();
    state.lenbits = 9;
    state.distcode = DISTFIX.as_ptr();
    state.distbits = 5;
}

/// `zlib_updatewindow()`.
///
/// Copies the last `wsize` or fewer output bytes into the circular window.
/// `out` is the `avail_out` this call started with; the bytes to window are
/// the `out - avail_out` immediately before `strm->next_out`.
///
/// # Safety
///
/// `strm->next_out` must have `out - strm->avail_out` readable bytes before
/// it, and `state->window` must cover `state->wsize` writable bytes.
unsafe fn updatewindow(strm: &mut ZStream, state: &mut InflateState, out: u32) {
    // SAFETY: the caller's contract.
    let window = unsafe {
        core::slice::from_raw_parts_mut(state.window, state.wsize as usize)
    };
    let mut copy = (out - strm.avail_out as u32) as usize;
    let wsize = state.wsize as usize;
    // SAFETY: as above -- `copy` bytes sit immediately before `next_out`.
    let src = unsafe { core::slice::from_raw_parts(strm.next_out.sub(copy), copy) };

    if copy >= wsize {
        window.copy_from_slice(&src[copy - wsize..]);
        state.write = 0;
        state.whave = state.wsize;
    } else {
        let write = state.write as usize;
        let mut dist = wsize - write;
        if dist > copy {
            dist = copy;
        }
        window[write..write + dist].copy_from_slice(&src[..dist]);
        copy -= dist;
        if copy != 0 {
            window[..copy].copy_from_slice(&src[dist..dist + copy]);
            state.write = copy as c_uint;
            state.whave = state.wsize;
        } else {
            state.write += dist as c_uint;
            if state.write == state.wsize {
                state.write = 0;
            }
            if state.whave < state.wsize {
                state.whave += dist as c_uint;
            }
        }
    }
}

/// `zlib_inflateSyncPacket()`.
fn inflate_sync_packet(state: &mut InflateState) -> c_int {
    if state.mode == STORED && state.bits == 0 {
        state.mode = TYPE;
        return Z_OK;
    }
    Z_DATA_ERROR
}

/// Set `strm->msg` and go to `BAD`. The C assigns a string literal; these are
/// the same bytes with the same NUL.
fn bad(strm: &mut ZStream, state: &mut InflateState, msg: &'static [u8]) {
    strm.msg = msg.as_ptr() as *mut c_char;
    state.mode = BAD;
}

/// The permutation of code lengths, `order[19]` in the C.
const ORDER: [u16; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// `LOAD()`. Rebuilt rather than mutated after `inflate_fast()` returns,
/// because that call writes the caller's output buffer through `strm` and a
/// `&mut [u8]` held across it would be aliased.
///
/// # Safety
///
/// The bases and lengths must describe the buffers `strm` was entered with,
/// and `strm->next_in`/`next_out` must still point inside them.
unsafe fn load<'a>(
    strm: *mut ZStream,
    in_base: *const u8,
    in_len: usize,
    out_base: *mut u8,
    out_len: usize,
) -> Regs<'a> {
    // SAFETY: the caller's contract.
    let s = unsafe { &mut *strm };
    // SAFETY: as above.
    let state = unsafe { &mut *s.state };
    Regs {
        // SAFETY: a zero-length slice may not be built from a null pointer,
        // and the C explicitly allows next_in == NULL when avail_in == 0.
        inp: if in_len == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(in_base, in_len) }
        },
        // SAFETY: `next_in` stays inside the buffer it was entered with.
        ipos: unsafe { s.next_in.offset_from(in_base) as usize },
        have: s.avail_in as u32,
        outp: if out_len == 0 {
            &mut []
        } else {
            unsafe { core::slice::from_raw_parts_mut(out_base, out_len) }
        },
        // SAFETY: as above.
        opos: unsafe { s.next_out.offset_from(out_base) as usize },
        left: s.avail_out as u32,
        hold: state.hold,
        bits: state.bits,
    }
}

/// `RESTORE()`.
///
/// # Safety
///
/// `strm` must be live and the bases must be the buffers it was entered with.
unsafe fn restore(strm: *mut ZStream, r: &Regs<'_>, in_base: *const u8, out_base: *mut u8) {
    // SAFETY: the caller's contract.
    let s = unsafe { &mut *strm };
    // SAFETY: as above.
    let state = unsafe { &mut *s.state };
    // SAFETY: both indices are within the buffers.
    unsafe {
        s.next_out = out_base.add(r.opos);
        s.next_in = in_base.add(r.ipos);
    }
    s.avail_out = r.left as c_ulong;
    s.avail_in = r.have as c_ulong;
    state.hold = r.hold;
    state.bits = r.bits;
}

/// `zlib_inflate()`.
///
/// Decodes as much input and produces as much output as it can before
/// returning. See the module docs for the one behavioural divergence, in
/// `MATCH`.
///
/// # Safety
///
/// `strm` may be null, and `strm->state` may be null. Otherwise both must be
/// live, `next_in` must have `avail_in` readable bytes (or be null with
/// `avail_in == 0`), and `next_out` must have `avail_out` writable bytes.
///
/// **That last precondition is stricter than the C's**, which carries a
/// comment permitting `next_out == NULL` with `avail_out != 0` for a ppc
/// zImage that inflated to address 0. Nothing in 6.18 does that — `grep`
/// finds no zlib under `arch/powerpc/boot/` — and the pre-boot path uses the
/// retained C in `inflate.c` regardless.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_inflate(strm: *mut ZStream, flush: c_int) -> c_int {
    if strm.is_null() {
        return Z_STREAM_ERROR;
    }
    // SAFETY: `strm` is live per the contract above.
    let s0 = unsafe { &mut *strm };
    if s0.state.is_null() || (s0.next_in.is_null() && s0.avail_in != 0) {
        return Z_STREAM_ERROR;
    }

    // SAFETY: `strm->state` is non-null and live.
    unsafe {
        if (*s0.state).mode == TYPE {
            (*s0.state).mode = TYPEDO;
        }
    }

    let in_base = s0.next_in;
    let in_len = s0.avail_in as usize;
    let out_base = s0.next_out;
    let out_len = s0.avail_out as usize;

    // SAFETY: the buffers are the caller's, as described above.
    let mut r = unsafe { load(strm, in_base, in_len, out_base, out_len) };
    let in_start = r.have;
    let mut out = r.left;
    let mut ret = Z_OK;

    'inf_leave: loop {
        // Re-derived every iteration so neither reference is held across the
        // `inflate_fast()` call in LEN.
        // SAFETY: both stay live for the whole call.
        let s = unsafe { &mut *strm };
        // SAFETY: as above.
        let state = unsafe { &mut *s.state };

        match state.mode {
            HEAD => {
                if state.wrap == 0 {
                    state.mode = TYPEDO;
                    continue;
                }
                if !r.needbits(16) {
                    break 'inf_leave;
                }
                // The C computes this in `unsigned long`, not `unsigned`.
                // It cannot differ here -- `hold` holds exactly 16 bits at
                // this point -- but the arithmetic is kept as written.
                if (((r.peek(8) as c_ulong) << 8) + (r.hold >> 8)) % 31 != 0 {
                    bad(s, state, MSG_HEADER_CHECK);
                    continue;
                }
                if r.peek(4) != Z_DEFLATED {
                    bad(s, state, MSG_UNKNOWN_METHOD);
                    continue;
                }
                r.drop(4);
                let len = r.peek(4) + 8;
                if len > state.wbits {
                    bad(s, state, MSG_WINDOW_SIZE);
                    continue;
                }
                state.dmax = 1u32 << len;
                state.check = adler32_init();
                s.adler = state.check;
                state.mode = if r.hold & 0x200 != 0 { DICTID } else { TYPE };
                r.initbits();
            }
            DICTID => {
                if !r.needbits(32) {
                    break 'inf_leave;
                }
                state.check = reverse(r.hold);
                s.adler = state.check;
                r.initbits();
                state.mode = DICT;
            }
            DICT => {
                if state.havedict == 0 {
                    // SAFETY: the bases are this call's buffers.
                    unsafe { restore(strm, &r, in_base, out_base) };
                    return Z_NEED_DICT;
                }
                state.check = adler32_init();
                s.adler = state.check;
                state.mode = TYPE;
            }
            TYPE | TYPEDO => {
                // TYPE falls through to TYPEDO **without** setting the mode,
                // so this is one arm. See the module docs.
                if state.mode == TYPE && flush == Z_BLOCK {
                    break 'inf_leave;
                }
                #[cfg(CONFIG_ZLIB_DFLTCC)]
                {
                    // SAFETY: `strm` is live; this is INFLATE_TYPEDO_HOOK.
                    if unsafe { dfltcc_can_inflate(strm) } != 0 {
                        // SAFETY: as above.
                        unsafe { restore(strm, &r, in_base, out_base) };
                        // SAFETY: as above.
                        let action = unsafe { dfltcc_inflate(strm, flush, &mut ret) };
                        // SAFETY: as above.
                        r = unsafe { load(strm, in_base, in_len, out_base, out_len) };
                        if action == DFLTCC_INFLATE_CONTINUE {
                            continue;
                        } else if action == DFLTCC_INFLATE_BREAK {
                            break 'inf_leave;
                        }
                    }
                }
                if state.last != 0 {
                    r.bytebits();
                    state.mode = CHECK;
                    continue;
                }
                if !r.needbits(3) {
                    break 'inf_leave;
                }
                state.last = r.peek(1) as c_int;
                r.drop(1);
                match r.peek(2) {
                    0 => state.mode = STORED,
                    1 => {
                        fixedtables(state);
                        state.mode = LEN;
                    }
                    2 => state.mode = TABLE,
                    _ => bad(s, state, MSG_BLOCK_TYPE),
                }
                r.drop(2);
            }
            STORED => {
                /* go to byte boundary */
                r.bytebits();
                if !r.needbits(32) {
                    break 'inf_leave;
                }
                if (r.hold & 0xffff) != ((r.hold >> 16) ^ 0xffff) {
                    bad(s, state, MSG_STORED_LENGTHS);
                    continue;
                }
                state.length = (r.hold as u32) & 0xffff;
                r.initbits();
                state.mode = COPY;
            }
            COPY => {
                let mut copy = state.length;
                if copy != 0 {
                    if copy > r.have {
                        copy = r.have;
                    }
                    if copy > r.left {
                        copy = r.left;
                    }
                    if copy == 0 {
                        break 'inf_leave;
                    }
                    let n = copy as usize;
                    r.outp[r.opos..r.opos + n].copy_from_slice(&r.inp[r.ipos..r.ipos + n]);
                    r.have -= copy;
                    r.ipos += n;
                    r.left -= copy;
                    r.opos += n;
                    state.length -= copy;
                    continue;
                }
                state.mode = TYPE;
            }
            TABLE => {
                if !r.needbits(14) {
                    break 'inf_leave;
                }
                state.nlen = r.peek(5) + 257;
                r.drop(5);
                state.ndist = r.peek(5) + 1;
                r.drop(5);
                state.ncode = r.peek(4) + 4;
                r.drop(4);
                if state.nlen > 286 || state.ndist > 30 {
                    bad(s, state, MSG_TOO_MANY);
                    continue;
                }
                state.have = 0;
                state.mode = LENLENS;
            }
            LENLENS => {
                while state.have < state.ncode {
                    if !r.needbits(3) {
                        break 'inf_leave;
                    }
                    state.lens[ORDER[state.have as usize] as usize] = r.peek(3) as u16;
                    state.have += 1;
                    r.drop(3);
                }
                while state.have < 19 {
                    state.lens[ORDER[state.have as usize] as usize] = 0;
                    state.have += 1;
                }
                state.next = state.codes.as_mut_ptr();
                state.lencode = state.next;
                state.lenbits = 7;
                // SAFETY: `lens` has 19 entries in range, `codes` has ENOUGH,
                // and `work` has 288 -- the contract inftrees_rs.rs documents.
                ret = unsafe {
                    zlib_inflate_table(
                        CODES,
                        state.lens.as_mut_ptr(),
                        19,
                        &mut state.next,
                        &mut state.lenbits,
                        state.work.as_mut_ptr(),
                    )
                };
                if ret != 0 {
                    bad(s, state, MSG_CODE_LENGTHS);
                    continue;
                }
                state.have = 0;
                state.mode = CODELENS;
            }
            CODELENS => {
                'codelens: while state.have < state.nlen + state.ndist {
                    let mut this;
                    loop {
                        // SAFETY: `lencode` addresses at least
                        // `1 << lenbits` entries; inftrees built it that way.
                        this = unsafe { *state.lencode.add(r.peek(state.lenbits) as usize) };
                        if this.bits as u32 <= r.bits {
                            break;
                        }
                        if !r.pullbyte() {
                            break 'inf_leave;
                        }
                    }
                    if this.val < 16 {
                        if !r.needbits(this.bits as u32) {
                            break 'inf_leave;
                        }
                        r.drop(this.bits as u32);
                        state.lens[state.have as usize] = this.val;
                        state.have += 1;
                    } else {
                        let len;
                        let mut copy;
                        if this.val == 16 {
                            if !r.needbits(this.bits as u32 + 2) {
                                break 'inf_leave;
                            }
                            r.drop(this.bits as u32);
                            if state.have == 0 {
                                bad(s, state, MSG_BIT_LENGTH_REPEAT);
                                break 'codelens;
                            }
                            len = state.lens[state.have as usize - 1];
                            copy = 3 + r.peek(2);
                            r.drop(2);
                        } else if this.val == 17 {
                            if !r.needbits(this.bits as u32 + 3) {
                                break 'inf_leave;
                            }
                            r.drop(this.bits as u32);
                            len = 0;
                            copy = 3 + r.peek(3);
                            r.drop(3);
                        } else {
                            if !r.needbits(this.bits as u32 + 7) {
                                break 'inf_leave;
                            }
                            r.drop(this.bits as u32);
                            len = 0;
                            copy = 11 + r.peek(7);
                            r.drop(7);
                        }
                        if state.have + copy > state.nlen + state.ndist {
                            bad(s, state, MSG_BIT_LENGTH_REPEAT);
                            break 'codelens;
                        }
                        while copy != 0 {
                            copy -= 1;
                            state.lens[state.have as usize] = len;
                            state.have += 1;
                        }
                    }
                }

                /* handle error breaks in while */
                if state.mode == BAD {
                    continue;
                }

                /* build code tables */
                state.next = state.codes.as_mut_ptr();
                state.lencode = state.next;
                state.lenbits = 9;
                // SAFETY: as at LENLENS.
                ret = unsafe {
                    zlib_inflate_table(
                        LENS,
                        state.lens.as_mut_ptr(),
                        state.nlen,
                        &mut state.next,
                        &mut state.lenbits,
                        state.work.as_mut_ptr(),
                    )
                };
                if ret != 0 {
                    bad(s, state, MSG_LITLEN_SET);
                    continue;
                }
                state.distcode = state.next;
                state.distbits = 6;
                let nlen = state.nlen as usize;
                // SAFETY: as above; `lens + nlen` has `ndist <= 30` entries.
                ret = unsafe {
                    zlib_inflate_table(
                        DISTS,
                        state.lens.as_mut_ptr().add(nlen),
                        state.ndist,
                        &mut state.next,
                        &mut state.distbits,
                        state.work.as_mut_ptr(),
                    )
                };
                if ret != 0 {
                    bad(s, state, MSG_DISTANCES_SET);
                    continue;
                }
                state.mode = LEN;
            }
            LEN => {
                if r.have >= 6 && r.left >= 258 {
                    // SAFETY: the bases are this call's buffers.
                    unsafe { restore(strm, &r, in_base, out_base) };
                    // SAFETY: `strm` is live and the entry contract holds --
                    // avail_in >= 6 and avail_out >= 258.
                    unsafe { inflate_fast(strm, out) };
                    // SAFETY: `inflate_fast` stays inside the same buffers.
                    r = unsafe { load(strm, in_base, in_len, out_base, out_len) };
                    continue;
                }
                let mut this;
                loop {
                    // SAFETY: as at CODELENS.
                    this = unsafe { *state.lencode.add(r.peek(state.lenbits) as usize) };
                    if this.bits as u32 <= r.bits {
                        break;
                    }
                    if !r.pullbyte() {
                        break 'inf_leave;
                    }
                }
                if this.op != 0 && (this.op & 0xf0) == 0 {
                    let last = this;
                    loop {
                        let idx = last.val as usize
                            + (r.peek(last.bits as u32 + last.op as u32) >> last.bits) as usize;
                        // SAFETY: `last.val` plus the sub-table index is
                        // inside the table inftrees built.
                        this = unsafe { *state.lencode.add(idx) };
                        if (last.bits + this.bits) as u32 <= r.bits {
                            break;
                        }
                        if !r.pullbyte() {
                            break 'inf_leave;
                        }
                    }
                    r.drop(last.bits as u32);
                }
                r.drop(this.bits as u32);
                state.length = this.val as c_uint;
                if this.op == 0 {
                    state.mode = LIT;
                    continue;
                }
                if this.op & 32 != 0 {
                    state.mode = TYPE;
                    continue;
                }
                if this.op & 64 != 0 {
                    bad(s, state, MSG_LITLEN_CODE);
                    continue;
                }
                state.extra = (this.op & 15) as c_uint;
                state.mode = LENEXT;
            }
            LENEXT => {
                if state.extra != 0 {
                    if !r.needbits(state.extra) {
                        break 'inf_leave;
                    }
                    state.length += r.peek(state.extra);
                    r.drop(state.extra);
                }
                state.mode = DIST;
            }
            DIST => {
                let mut this;
                loop {
                    // SAFETY: as at LEN.
                    this = unsafe { *state.distcode.add(r.peek(state.distbits) as usize) };
                    if this.bits as u32 <= r.bits {
                        break;
                    }
                    if !r.pullbyte() {
                        break 'inf_leave;
                    }
                }
                if (this.op & 0xf0) == 0 {
                    let last = this;
                    loop {
                        let idx = last.val as usize
                            + (r.peek(last.bits as u32 + last.op as u32) >> last.bits) as usize;
                        // SAFETY: as above.
                        this = unsafe { *state.distcode.add(idx) };
                        if (last.bits + this.bits) as u32 <= r.bits {
                            break;
                        }
                        if !r.pullbyte() {
                            break 'inf_leave;
                        }
                    }
                    r.drop(last.bits as u32);
                }
                r.drop(this.bits as u32);
                if this.op & 64 != 0 {
                    bad(s, state, MSG_DISTANCE_CODE);
                    continue;
                }
                state.offset = this.val as c_uint;
                state.extra = (this.op & 15) as c_uint;
                state.mode = DISTEXT;
            }
            DISTEXT => {
                if state.extra != 0 {
                    if !r.needbits(state.extra) {
                        break 'inf_leave;
                    }
                    state.offset += r.peek(state.extra);
                    r.drop(state.extra);
                }
                /* INFLATE_STRICT's state->offset > state->dmax test is not
                 * compiled in the kernel and is not ported. */
                // `whave + out` is `unsigned` arithmetic in the C and can
                // wrap on an absurd avail_out; wrapping here rather than
                // panicking is the faithful reading.
                if state.offset > state.whave.wrapping_add(out).wrapping_sub(r.left) {
                    bad(s, state, MSG_DIST_TOO_FAR);
                    continue;
                }
                state.mode = MATCH;
            }
            MATCH => {
                if r.left == 0 {
                    break 'inf_leave;
                }
                let mut copy = out - r.left;
                let from_window;
                let from_idx;
                if state.offset > copy {
                    /* copy from window */
                    copy = state.offset - copy;
                    // THE ONE DELIBERATE DIVERGENCE. See the module docs and
                    // upstream/zlib-inflate-oob/. Without this the next line
                    // underflows and indexes before the window.
                    if copy > state.whave {
                        bad(s, state, MSG_DIST_TOO_FAR);
                        continue;
                    }
                    if copy > state.write {
                        copy -= state.write;
                        from_idx = (state.wsize - copy) as usize;
                    } else {
                        from_idx = (state.write - copy) as usize;
                    }
                    if copy > state.length {
                        copy = state.length;
                    }
                    from_window = true;
                } else {
                    /* copy from output */
                    from_idx = r.opos - state.offset as usize;
                    copy = state.length;
                    from_window = false;
                }
                if copy > r.left {
                    copy = r.left;
                }
                r.left -= copy;
                state.length -= copy;

                let n = copy as usize;
                if from_window {
                    // SAFETY: `window` covers `wsize` bytes and the guard
                    // above bounds `from_idx + n` by `wsize`.
                    let window = unsafe {
                        core::slice::from_raw_parts(state.window, state.wsize as usize)
                    };
                    r.outp[r.opos..r.opos + n].copy_from_slice(&window[from_idx..from_idx + n]);
                } else {
                    // A forward byte copy, NOT a memmove: an LZ77 match may
                    // overlap its own destination and the repetition is the
                    // point.
                    for k in 0..n {
                        r.outp[r.opos + k] = r.outp[from_idx + k];
                    }
                }
                r.opos += n;

                if state.length == 0 {
                    state.mode = LEN;
                }
            }
            LIT => {
                if r.left == 0 {
                    break 'inf_leave;
                }
                r.outp[r.opos] = state.length as u8;
                r.opos += 1;
                r.left -= 1;
                state.mode = LEN;
            }
            CHECK => {
                if state.wrap != 0 {
                    if !r.needbits(32) {
                        break 'inf_leave;
                    }
                    out -= r.left;
                    s.total_out += out as c_ulong;
                    state.total += out as c_ulong;
                    // SAFETY: `strm` is live; this is INFLATE_NEED_CHECKSUM.
                    if unsafe { inflate_need_software(strm) } && out != 0 {
                        let start = r.opos - out as usize;
                        state.check = adler32(state.check, &r.outp[start..r.opos]);
                        s.adler = state.check;
                    }
                    out = r.left;
                    if reverse(r.hold) != state.check {
                        bad(s, state, MSG_DATA_CHECK);
                        continue;
                    }
                    r.initbits();
                }
                state.mode = DONE;
            }
            DONE => {
                ret = Z_STREAM_END;
                break 'inf_leave;
            }
            BAD => {
                ret = Z_DATA_ERROR;
                break 'inf_leave;
            }
            MEM => return Z_MEM_ERROR,
            _ => return Z_STREAM_ERROR,
        }
    }

    // Return from inflate(), updating the total counts and the check value.
    // SAFETY: the bases are this call's buffers.
    unsafe { restore(strm, &r, in_base, out_base) };
    // SAFETY: `strm` and its state are live.
    let s = unsafe { &mut *strm };
    // SAFETY: as above.
    let state = unsafe { &mut *s.state };

    // SAFETY: `strm` is live; this is INFLATE_NEED_UPDATEWINDOW.
    if unsafe { inflate_need_software(strm) }
        && (state.wsize != 0 || (state.mode < CHECK && out != s.avail_out as u32))
    {
        // SAFETY: `out - avail_out` bytes sit before `next_out` inside the
        // caller's buffer, and `window` covers `wsize` bytes.
        unsafe { updatewindow(s, state, out) };
    }

    let in_used = in_start - s.avail_in as u32;
    out -= s.avail_out as u32;
    s.total_in += in_used as c_ulong;
    s.total_out += out as c_ulong;
    state.total += out as c_ulong;
    // SAFETY: `strm` is live.
    if unsafe { inflate_need_software(strm) } && state.wrap != 0 && out != 0 {
        // SAFETY: `out` bytes sit immediately before `next_out`.
        let written = unsafe {
            core::slice::from_raw_parts(s.next_out.sub(out as usize), out as usize)
        };
        state.check = adler32(state.check, written);
        s.adler = state.check;
    }

    s.data_type = state.bits as c_int
        + if state.last != 0 { 64 } else { 0 }
        + if state.mode == TYPE { 128 } else { 0 };

    if flush == Z_PACKET_FLUSH && ret == Z_OK && s.avail_out != 0 && s.avail_in == 0 {
        return inflate_sync_packet(state);
    }

    if ((in_used == 0 && out == 0) || flush == Z_FINISH) && ret == Z_OK {
        ret = Z_BUF_ERROR;
    }

    ret
}

/// `zlib_inflateIncomp()`.
///
/// Adds the data at `next_in`/`avail_in` to the output history without
/// producing output. The state must be waiting at the start of a block.
///
/// # Safety
///
/// `strm` and `strm->state` must be live, and `next_in` must have `avail_in`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_zlib_inflateIncomp(strm: *mut ZStream) -> c_int {
    // SAFETY: the caller's contract.
    let z = unsafe { &mut *strm };
    // SAFETY: as above.
    let state = unsafe { &mut *z.state };

    if state.mode != TYPE && state.mode != HEAD {
        return Z_DATA_ERROR;
    }

    let saved_no = z.next_out;
    let saved_ao = z.avail_out;
    let avail_in = z.avail_in;

    /* Setup some variables to allow misuse of updateWindow */
    z.avail_out = 0;
    // SAFETY: `next_in` has `avail_in` readable bytes, so this is one past the
    // end of them -- which is what updatewindow() reads backwards from.
    z.next_out = unsafe { (z.next_in as *mut u8).add(avail_in as usize) };

    // SAFETY: the `copy` it computes is `avail_in`, and those bytes sit
    // immediately before the `next_out` faked above.
    unsafe { updatewindow(z, state, avail_in as u32) };

    /* Restore saved variables */
    z.avail_out = saved_ao;
    z.next_out = saved_no;

    // SAFETY: `next_in` has `avail_in` readable bytes.
    let consumed =
        unsafe { core::slice::from_raw_parts(z.next_in, avail_in as usize) };
    state.check = adler32(state.check, consumed);
    z.adler = state.check;

    z.total_out += avail_in;
    z.total_in += avail_in;
    // SAFETY: one past the end of the input buffer is a valid pointer value.
    z.next_in = unsafe { z.next_in.add(avail_in as usize) };
    state.total += avail_in;
    z.avail_in = 0;

    Z_OK
}
