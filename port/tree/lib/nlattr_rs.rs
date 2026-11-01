// SPDX-License-Identifier: GPL-2.0

//! Netlink attribute parsing and validation -- the Rust behind `lib/nlattr.c`.
//!
//! Ported from `lib/nlattr.c` (6.18.49), "NETLINK Netlink attributes" by Thomas Graf and Alexey Kuznetsov: the walk over a stream
//! of `struct nlattr` (`__nla_validate_parse`, shared by `__nla_validate` and `__nla_parse`), the per-attribute policy check
//! (`validate_nla` and its range / mask / bitfield / array helpers), `nla_policy_len`, `nla_find`, `nla_get_range_unsigned/signed`
//! and the byte-wise helpers `nla_strscpy`, `nla_memcpy`, `nla_memcmp`, `nla_strcmp`.
//!
//! # What stays C (`nlattr_glue.c`)
//! * All the exported entry points (`EXPORT_SYMBOL`'d: their MODVERSIONS fingerprints come from the DWARF of the definition); each is
//!   a thunk into a `rust_nla_*` function here. Nothing else in the build calls this file.
//! * Everything that touches `struct sk_buff`: `__nla_reserve*`, `nla_reserve*`, `__nla_put*`, `nla_put*`, `nla_append`, and
//!   `nla_strdup` (`kmalloc`).
//! * Every macro that plants a bug-table or rate-limit entry naming the file and line: the `WARN_ON_ONCE`/`WARN_ON` sites, the
//!   `BUG_ON` in `validate_nla` and the three `pr_warn_ratelimited` sites (which print `current->comm`). Each has its own
//!   one-line C helper (`rust_nla_warn_*`, `rust_nla_pr_*`) so it keeps its own once-flag / rate-limit state, as it had in C.
//!   The warning's file and line now name the glue, not `nlattr.c`: the recorded divergence for this port.
//!
//! The extack messages are byte-for-byte the C's strings. `NL_SET_ERR_MSG*()` is `do_trace_netlink_extack(msg)` (a plain exported
//! function, not a static-key inline) plus up to three stores into `struct netlink_ext_ack`; both are done here.
//!
//! # `array_index_nospec`
//! x86's `cmp; sbb` mask, as `asm!`: a speculatively out-of-range `type` becomes 0 before it indexes the policy or `tb[]`.
//!
//! Replaces: lib/nlattr.c (the parsing, validation and read-only helpers; the skb builders and `nla_strdup` stay C)

use core::ffi::{c_char, c_int, c_uint, c_void};

#[cfg(not(all(target_arch = "x86_64", target_endian = "little")))]
compile_error!("nlattr_rs.rs: x86-64 little-endian only (the union in struct nla_policy, array_index_nospec)");

const EINVAL: c_int = 22;
const ERANGE: c_int = 34;

const NLA_HDRLEN: c_int = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

// enum { NLA_UNSPEC, ... }
const NLA_UNSPEC: u8 = 0;
const NLA_U8: u8 = 1;
const NLA_U16: u8 = 2;
const NLA_U32: u8 = 3;
const NLA_U64: u8 = 4;
const NLA_STRING: u8 = 5;
const NLA_FLAG: u8 = 6;
const NLA_MSECS: u8 = 7;
const NLA_NESTED: u8 = 8;
const NLA_NESTED_ARRAY: u8 = 9;
const NLA_NUL_STRING: u8 = 10;
const NLA_BINARY: u8 = 11;
const NLA_S8: u8 = 12;
const NLA_S16: u8 = 13;
const NLA_S32: u8 = 14;
const NLA_S64: u8 = 15;
const NLA_BITFIELD32: u8 = 16;
const NLA_REJECT: u8 = 17;
const NLA_BE16: u8 = 18;
const NLA_BE32: u8 = 19;
const NLA_SINT: u8 = 20;
const NLA_UINT: u8 = 21;
/// `NLA_TYPE_MAX` = `__NLA_TYPE_MAX - 1`.
const NLA_TYPE_MAX: usize = 21;

// enum nla_policy_validation
const NLA_VALIDATE_NONE: u8 = 0;
const NLA_VALIDATE_RANGE: u8 = 1;
const NLA_VALIDATE_RANGE_WARN_TOO_LONG: u8 = 2;
const NLA_VALIDATE_MIN: u8 = 3;
const NLA_VALIDATE_MAX: u8 = 4;
const NLA_VALIDATE_MASK: u8 = 5;
const NLA_VALIDATE_RANGE_PTR: u8 = 6;
const NLA_VALIDATE_FUNCTION: u8 = 7;

// enum netlink_validation
const NL_VALIDATE_TRAILING: c_uint = 1 << 0;
const NL_VALIDATE_MAXTYPE: c_uint = 1 << 1;
const NL_VALIDATE_UNSPEC: c_uint = 1 << 2;
const NL_VALIDATE_STRICT_ATTRS: c_uint = 1 << 3;
const NL_VALIDATE_NESTED: c_uint = 1 << 4;
/// `NL_VALIDATE_STRICT`.
const NL_VALIDATE_STRICT: c_uint =
    NL_VALIDATE_TRAILING | NL_VALIDATE_MAXTYPE | NL_VALIDATE_UNSPEC | NL_VALIDATE_STRICT_ATTRS | NL_VALIDATE_NESTED;

/// `MAX_POLICY_RECURSION_DEPTH`.
const MAX_POLICY_RECURSION_DEPTH: c_uint = 10;

/// `struct nlattr`, `include/uapi/linux/netlink.h`.
#[repr(C)]
pub struct Nlattr {
    nla_len: u16,
    nla_type: u16,
}

/// `struct nla_policy`, `include/net/netlink.h`: `type`, `validation_type`, `len`, then an 8-byte union at offset 8. The union is kept
/// as its raw 64 bits; the accessors below read the member the C reads (all little-endian prefixes of the same word).
#[repr(C)]
pub struct NlaPolicy {
    type_: u8,
    validation_type: u8,
    len: u16,
    u: u64,
}

const _: () = assert!(core::mem::size_of::<NlaPolicy>() == 16);
const _: () = assert!(core::mem::offset_of!(NlaPolicy, u) == 8); // C: offsetof(struct nla_policy, <union>) == 8

impl NlaPolicy {
    /// `strict_start_type` (u16).
    fn strict_start_type(&self) -> u16 {
        self.u as u16
    }
    /// `bitfield32_valid` / `mask` (u32).
    fn mask32(&self) -> u32 {
        self.u as u32
    }
    /// `min` (s16, first half of the anonymous struct).
    fn min16(&self) -> i16 {
        self.u as u16 as i16
    }
    /// `max` (s16, second half).
    fn max16(&self) -> i16 {
        (self.u >> 16) as u16 as i16
    }
    /// The pointer members (`reject_message`, `nested_policy`, `range`, `range_signed`).
    fn ptr(&self) -> *const c_void {
        self.u as usize as *const c_void
    }
}

/// `struct netlink_range_validation`.
#[repr(C)]
pub struct NetlinkRangeValidation {
    min: u64,
    max: u64,
}

/// `struct netlink_range_validation_signed`.
#[repr(C)]
pub struct NetlinkRangeValidationSigned {
    min: i64,
    max: i64,
}

/// The first three fields of `struct netlink_ext_ack` (`include/linux/netlink.h`); nothing else is touched here.
#[repr(C)]
pub struct NetlinkExtAck {
    msg: *const c_char,
    bad_attr: *const Nlattr,
    policy: *const NlaPolicy,
}

/// `nla_policy::validate`'s type.
type ValidateFn = unsafe extern "C" fn(*const Nlattr, *mut NetlinkExtAck) -> c_int;

extern "C" {
    /// `net/netlink/af_netlink.c`.
    fn do_trace_netlink_extack(msg: *const c_char);
    /// The kernel's `memcmp()` / `strlen()` (lib/string.c).
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
    fn strlen(s: *const c_char) -> usize;
    // nlattr_glue.c: one helper per macro site that must keep its own bug-table / rate-limit state.
    fn rust_nla_warn_range_unsigned_neg(cond: bool);
    fn rust_nla_warn_range_unsigned_default();
    fn rust_nla_warn_range_signed_default();
    fn rust_nla_warn_int_range_default();
    fn rust_nla_bug_on_type(cond: bool);
    fn rust_nla_pr_invalid_len(ty: c_int);
    fn rust_nla_pr_invalid_len_range(ty: c_int);
    fn rust_nla_pr_leftover(rem: c_int);
}

/// `nla_attr_len[]`.
static NLA_ATTR_LEN: [u8; NLA_TYPE_MAX + 1] = {
    let mut t = [0u8; NLA_TYPE_MAX + 1];
    t[NLA_U8 as usize] = 1;
    t[NLA_U16 as usize] = 2;
    t[NLA_U32 as usize] = 4;
    t[NLA_U64 as usize] = 8;
    t[NLA_S8 as usize] = 1;
    t[NLA_S16 as usize] = 2;
    t[NLA_S32 as usize] = 4;
    t[NLA_S64 as usize] = 8;
    t[NLA_BE16 as usize] = 2;
    t[NLA_BE32 as usize] = 4;
    t
};

/// `nla_attr_minlen[]`.
static NLA_ATTR_MINLEN: [u8; NLA_TYPE_MAX + 1] = {
    let mut t = [0u8; NLA_TYPE_MAX + 1];
    t[NLA_U8 as usize] = 1;
    t[NLA_U16 as usize] = 2;
    t[NLA_U32 as usize] = 4;
    t[NLA_U64 as usize] = 8;
    t[NLA_MSECS as usize] = 8;
    t[NLA_NESTED as usize] = NLA_HDRLEN as u8;
    t[NLA_S8 as usize] = 1;
    t[NLA_S16 as usize] = 2;
    t[NLA_S32 as usize] = 4;
    t[NLA_S64 as usize] = 8;
    t[NLA_BE16 as usize] = 2;
    t[NLA_BE32 as usize] = 4;
    t
};

// ---------------------------------------------------------------------------
// netlink.h / skbuff-free inline helpers
// ---------------------------------------------------------------------------

/// `nla_len()`.
#[inline(always)]
unsafe fn nla_len(nla: *const Nlattr) -> c_int {
    // SAFETY: caller contract (`nla` readable).
    unsafe { (*nla).nla_len as c_int - NLA_HDRLEN }
}

/// `nla_type()`.
#[inline(always)]
unsafe fn nla_type(nla: *const Nlattr) -> c_int {
    // SAFETY: as above.
    unsafe { ((*nla).nla_type & NLA_TYPE_MASK) as c_int }
}

/// `nla_data()`.
#[inline(always)]
unsafe fn nla_data(nla: *const Nlattr) -> *const u8 {
    nla.cast::<u8>().wrapping_add(NLA_HDRLEN as usize)
}

/// `nla_ok()`.
#[inline(always)]
unsafe fn nla_ok(nla: *const Nlattr, remaining: c_int) -> bool {
    // SAFETY: `remaining >= 4` is tested first, so the header is readable.
    remaining >= 4 && unsafe { (*nla).nla_len } >= 4 && unsafe { (*nla).nla_len } as c_int <= remaining
}

/// `nla_next()`.
#[inline(always)]
unsafe fn nla_next(nla: *const Nlattr, remaining: &mut c_int) -> *const Nlattr {
    // SAFETY: `nla` readable (it passed `nla_ok`).
    let totlen = ((unsafe { (*nla).nla_len } as c_uint) + 3) & !3;
    *remaining = remaining.wrapping_sub(totlen as c_int);
    nla.cast::<u8>().wrapping_add(totlen as usize).cast::<Nlattr>()
}

/// `array_index_nospec(index, size)` on x86-64.
#[inline(always)]
fn array_index_nospec(index: u64, size: u64) -> u64 {
    let mask: u64;
    // SAFETY: pure register arithmetic; `cmp; sbb` sets `mask` to all ones iff `index < size` (unsigned).
    unsafe {
        core::arch::asm!("cmp {idx}, {size}", "sbb {m}, {m}", idx = in(reg) index, size = in(reg) size, m = out(reg) mask,
            options(pure, nomem, nostack));
    }
    index & mask
}

/// Reads of the attribute payload; the stream's alignment is the sender's business, so every read is unaligned.
#[inline(always)]
unsafe fn get_u8(nla: *const Nlattr) -> u8 {
    // SAFETY: payload of at least 1 byte (the length checks before every call).
    unsafe { nla_data(nla).read_unaligned() }
}
#[inline(always)]
unsafe fn get_u16(nla: *const Nlattr) -> u16 {
    // SAFETY: as above, 2 bytes.
    unsafe { nla_data(nla).cast::<u16>().read_unaligned() }
}
#[inline(always)]
unsafe fn get_u32(nla: *const Nlattr) -> u32 {
    // SAFETY: as above, 4 bytes.
    unsafe { nla_data(nla).cast::<u32>().read_unaligned() }
}
/// `nla_get_u64()` / `nla_get_s64()`: the C copies with `nla_memcpy(&tmp, nla, 8)`, i.e. `min(8, nla_len)` bytes and zero fill, so a
/// short attribute never reads past its payload.
#[inline(always)]
unsafe fn get_u64(nla: *const Nlattr) -> u64 {
    let mut tmp: u64 = 0;
    // SAFETY: at most `nla_len` bytes of the payload are read.
    unsafe {
        let n = core::cmp::min(8, nla_len(nla));
        if n > 0 {
            core::ptr::copy_nonoverlapping(nla_data(nla), (&raw mut tmp).cast::<u8>(), n as usize);
        }
    }
    tmp
}
/// `nla_get_uint()`.
#[inline(always)]
unsafe fn get_uint(nla: *const Nlattr) -> u64 {
    // SAFETY: as above.
    unsafe {
        if nla_len(nla) as usize == 4 {
            get_u32(nla) as u64
        } else {
            get_u64(nla)
        }
    }
}
/// `nla_get_sint()`.
#[inline(always)]
unsafe fn get_sint(nla: *const Nlattr) -> i64 {
    // SAFETY: as above.
    unsafe {
        if nla_len(nla) as usize == 4 {
            get_u32(nla) as i32 as i64
        } else {
            get_u64(nla) as i64
        }
    }
}

// ---------------------------------------------------------------------------
// extack (NL_SET_ERR_MSG family)
// ---------------------------------------------------------------------------

/// `NL_SET_ERR_MSG(extack, msg)`; `msg` is NUL-terminated.
#[inline(always)]
unsafe fn set_err_msg(extack: *mut NetlinkExtAck, msg: &'static [u8]) {
    // SAFETY: `extack` is null or valid (caller); `msg` is a static C string.
    unsafe {
        do_trace_netlink_extack(msg.as_ptr().cast());
        if !extack.is_null() {
            (*extack).msg = msg.as_ptr().cast();
        }
    }
}

/// `NL_SET_ERR_MSG_ATTR_POL(extack, attr, pol, msg)`; `NL_SET_ERR_MSG_ATTR` is the same with `pol == NULL`.
#[inline(always)]
unsafe fn set_err_attr_pol(extack: *mut NetlinkExtAck, attr: *const Nlattr, pol: *const NlaPolicy, msg: &'static [u8]) {
    // SAFETY: as `set_err_msg`.
    unsafe {
        do_trace_netlink_extack(msg.as_ptr().cast());
        if !extack.is_null() {
            (*extack).msg = msg.as_ptr().cast();
            (*extack).bad_attr = attr;
            (*extack).policy = pol;
        }
    }
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

/// `validate_nla_bitfield32()`: the attribute payload is `{ u32 value; u32 selector; }`.
unsafe fn validate_nla_bitfield32(nla: *const Nlattr, valid_flags_mask: u32) -> c_int {
    // SAFETY: the caller checked `nla_len == 8`.
    let (value, selector) = unsafe { (get_u32(nla), nla_data(nla).add(4).cast::<u32>().read_unaligned()) };

    if valid_flags_mask == 0 {
        return -EINVAL;
    }
    /* disallow invalid bit selector */
    if selector & !valid_flags_mask != 0 {
        return -EINVAL;
    }
    /* disallow invalid bit values */
    if value & !valid_flags_mask != 0 {
        return -EINVAL;
    }
    /* disallow valid bit values that are not selected */
    if value & !selector != 0 {
        return -EINVAL;
    }
    0
}

/// `nla_validate_array()`.
unsafe fn nla_validate_array(
    head: *const Nlattr,
    len: c_int,
    maxtype: c_int,
    policy: *const NlaPolicy,
    extack: *mut NetlinkExtAck,
    validate: c_uint,
    depth: c_uint,
) -> c_int {
    // SAFETY: caller contract (`head`..`head+len` readable, `policy` has `maxtype + 1` entries).
    unsafe {
        let mut entry = head;
        let mut rem = len;
        while nla_ok(entry, rem) {
            if nla_len(entry) != 0 {
                if nla_len(entry) < NLA_HDRLEN {
                    set_err_attr_pol(extack, entry, policy, b"Array element too short\0");
                    return -ERANGE;
                }

                let ret = nla_validate_parse(
                    nla_data(entry).cast(),
                    nla_len(entry),
                    maxtype,
                    policy,
                    validate,
                    extack,
                    core::ptr::null_mut(),
                    depth + 1,
                );
                if ret < 0 {
                    return ret;
                }
            }
            entry = nla_next(entry, &mut rem);
        }
        0
    }
}

/// `nla_get_range_unsigned()`.
///
/// # Safety
/// `pt` and `range` are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_get_range_unsigned(pt: *const NlaPolicy, range: *mut NetlinkRangeValidation) {
    // SAFETY: caller contract.
    unsafe {
        let pt = &*pt;
        rust_nla_warn_range_unsigned_neg(
            pt.validation_type != NLA_VALIDATE_RANGE_PTR && (pt.min16() < 0 || pt.max16() < 0),
        );

        (*range).min = 0;

        match pt.type_ {
            NLA_U8 => (*range).max = u8::MAX as u64,
            NLA_U16 | NLA_BE16 | NLA_BINARY => (*range).max = u16::MAX as u64,
            NLA_U32 | NLA_BE32 => (*range).max = u32::MAX as u64,
            NLA_U64 | NLA_UINT | NLA_MSECS => (*range).max = u64::MAX,
            _ => {
                rust_nla_warn_range_unsigned_default();
                return;
            }
        }

        match pt.validation_type {
            NLA_VALIDATE_RANGE | NLA_VALIDATE_RANGE_WARN_TOO_LONG => {
                (*range).min = pt.min16() as i64 as u64;
                (*range).max = pt.max16() as i64 as u64;
            }
            NLA_VALIDATE_RANGE_PTR => {
                let r = pt.ptr().cast::<NetlinkRangeValidation>();
                (*range).min = (*r).min;
                (*range).max = (*r).max;
            }
            NLA_VALIDATE_MIN => (*range).min = pt.min16() as i64 as u64,
            NLA_VALIDATE_MAX => (*range).max = pt.max16() as i64 as u64,
            _ => {}
        }
    }
}

/// `nla_validate_range_unsigned()`.
unsafe fn nla_validate_range_unsigned(
    pt: *const NlaPolicy,
    nla: *const Nlattr,
    extack: *mut NetlinkExtAck,
    validate: c_uint,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let ptr = &*pt;
        let value: u64 = match ptr.type_ {
            NLA_U8 => get_u8(nla) as u64,
            NLA_U16 => get_u16(nla) as u64,
            NLA_U32 => get_u32(nla) as u64,
            NLA_U64 => get_u64(nla),
            NLA_UINT => get_uint(nla),
            NLA_MSECS => get_u64(nla),
            NLA_BINARY => nla_len(nla) as i64 as u64,
            NLA_BE16 => u16::from_be(get_u16(nla)) as u64,
            NLA_BE32 => u32::from_be(get_u32(nla)) as u64,
            _ => return -EINVAL,
        };

        let mut range = NetlinkRangeValidation { min: 0, max: 0 };
        rust_nla_get_range_unsigned(pt, &mut range);

        if ptr.validation_type == NLA_VALIDATE_RANGE_WARN_TOO_LONG && ptr.type_ == NLA_BINARY && value > range.max {
            rust_nla_pr_invalid_len_range(ptr.type_ as c_int);
            if validate & NL_VALIDATE_STRICT_ATTRS != 0 {
                set_err_attr_pol(extack, nla, pt, b"invalid attribute length\0");
                return -EINVAL;
            }

            /* this assumes min <= max (don't validate against min) */
            return 0;
        }

        if value < range.min || value > range.max {
            if ptr.type_ == NLA_BINARY {
                set_err_attr_pol(extack, nla, pt, b"binary attribute size out of range\0");
            } else {
                set_err_attr_pol(extack, nla, pt, b"integer out of range\0");
            }

            return -ERANGE;
        }

        0
    }
}

/// `nla_get_range_signed()`.
///
/// # Safety
/// `pt` and `range` are valid.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_get_range_signed(pt: *const NlaPolicy, range: *mut NetlinkRangeValidationSigned) {
    // SAFETY: caller contract.
    unsafe {
        let pt = &*pt;
        match pt.type_ {
            NLA_S8 => {
                (*range).min = i8::MIN as i64;
                (*range).max = i8::MAX as i64;
            }
            NLA_S16 => {
                (*range).min = i16::MIN as i64;
                (*range).max = i16::MAX as i64;
            }
            NLA_S32 => {
                (*range).min = i32::MIN as i64;
                (*range).max = i32::MAX as i64;
            }
            NLA_S64 | NLA_SINT => {
                (*range).min = i64::MIN;
                (*range).max = i64::MAX;
            }
            _ => {
                rust_nla_warn_range_signed_default();
                return;
            }
        }

        match pt.validation_type {
            NLA_VALIDATE_RANGE => {
                (*range).min = pt.min16() as i64;
                (*range).max = pt.max16() as i64;
            }
            NLA_VALIDATE_RANGE_PTR => {
                let r = pt.ptr().cast::<NetlinkRangeValidationSigned>();
                (*range).min = (*r).min;
                (*range).max = (*r).max;
            }
            NLA_VALIDATE_MIN => (*range).min = pt.min16() as i64,
            NLA_VALIDATE_MAX => (*range).max = pt.max16() as i64,
            _ => {}
        }
    }
}

/// `nla_validate_int_range_signed()`.
unsafe fn nla_validate_int_range_signed(pt: *const NlaPolicy, nla: *const Nlattr, extack: *mut NetlinkExtAck) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let value: i64 = match (*pt).type_ {
            NLA_S8 => get_u8(nla) as i8 as i64,
            NLA_S16 => get_u16(nla) as i16 as i64,
            NLA_S32 => get_u32(nla) as i32 as i64,
            NLA_S64 => get_u64(nla) as i64,
            NLA_SINT => get_sint(nla),
            _ => return -EINVAL,
        };

        let mut range = NetlinkRangeValidationSigned { min: 0, max: 0 };
        rust_nla_get_range_signed(pt, &mut range);

        if value < range.min || value > range.max {
            set_err_attr_pol(extack, nla, pt, b"integer out of range\0");
            return -ERANGE;
        }

        0
    }
}

/// `nla_validate_int_range()`.
unsafe fn nla_validate_int_range(
    pt: *const NlaPolicy,
    nla: *const Nlattr,
    extack: *mut NetlinkExtAck,
    validate: c_uint,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        match (*pt).type_ {
            NLA_U8 | NLA_U16 | NLA_U32 | NLA_U64 | NLA_UINT | NLA_MSECS | NLA_BINARY | NLA_BE16 | NLA_BE32 => {
                nla_validate_range_unsigned(pt, nla, extack, validate)
            }
            NLA_S8 | NLA_S16 | NLA_S32 | NLA_S64 | NLA_SINT => nla_validate_int_range_signed(pt, nla, extack),
            _ => {
                rust_nla_warn_int_range_default();
                -EINVAL
            }
        }
    }
}

/// `nla_validate_mask()`.
unsafe fn nla_validate_mask(pt: *const NlaPolicy, nla: *const Nlattr, extack: *mut NetlinkExtAck) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let value: u64 = match (*pt).type_ {
            NLA_U8 => get_u8(nla) as u64,
            NLA_U16 => get_u16(nla) as u64,
            NLA_U32 => get_u32(nla) as u64,
            NLA_U64 => get_u64(nla),
            NLA_UINT => get_uint(nla),
            NLA_BE16 => u16::from_be(get_u16(nla)) as u64,
            NLA_BE32 => u32::from_be(get_u32(nla)) as u64,
            _ => return -EINVAL,
        };

        if value & !((*pt).mask32() as u64) != 0 {
            set_err_attr_pol(extack, nla, core::ptr::null(), b"reserved bit set\0");
            return -EINVAL;
        }

        0
    }
}

/// `validate_nla()`: check one attribute against its policy entry.
unsafe fn validate_nla(
    nla: *const Nlattr,
    maxtype: c_int,
    policy: *const NlaPolicy,
    mut validate: c_uint,
    extack: *mut NetlinkExtAck,
    depth: c_uint,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let strict_start_type = (*policy).strict_start_type();
        let minlen: c_int;
        let mut attrlen = nla_len(nla);
        let mut ty = nla_type(nla);
        let mut err: c_int = -ERANGE;

        if strict_start_type != 0 && ty >= strict_start_type as c_int {
            validate |= NL_VALIDATE_STRICT;
        }

        if ty <= 0 || ty > maxtype {
            return 0;
        }

        ty = array_index_nospec(ty as i64 as u64, (maxtype + 1) as i64 as u64) as c_int;
        let pt = policy.add(ty as usize);
        let p = &*pt;

        rust_nla_bug_on_type(p.type_ as usize > NLA_TYPE_MAX);

        if NLA_ATTR_LEN[p.type_ as usize] != 0 && attrlen != NLA_ATTR_LEN[p.type_ as usize] as c_int {
            rust_nla_pr_invalid_len(ty);
            if validate & NL_VALIDATE_STRICT_ATTRS != 0 {
                set_err_attr_pol(extack, nla, pt, b"invalid attribute length\0");
                return -EINVAL;
            }
        }

        if validate & NL_VALIDATE_NESTED != 0 {
            if (p.type_ == NLA_NESTED || p.type_ == NLA_NESTED_ARRAY) && (*nla).nla_type & NLA_F_NESTED == 0 {
                set_err_attr_pol(extack, nla, pt, b"NLA_F_NESTED is missing\0");
                return -EINVAL;
            }
            if p.type_ != NLA_NESTED
                && p.type_ != NLA_NESTED_ARRAY
                && p.type_ != NLA_UNSPEC
                && (*nla).nla_type & NLA_F_NESTED != 0
            {
                set_err_attr_pol(extack, nla, pt, b"NLA_F_NESTED not expected\0");
                return -EINVAL;
            }
        }

        // `goto out_err` is a `break 'check` carrying nothing: `err` is already set where the C sets it.
        'check: {
            match p.type_ {
                NLA_REJECT => {
                    let msg = p.ptr().cast::<c_char>();
                    if !extack.is_null() && !msg.is_null() {
                        (*extack).bad_attr = nla;
                        (*extack).policy = core::ptr::null();
                        (*extack).msg = msg;
                        return -EINVAL;
                    }
                    err = -EINVAL;
                    break 'check;
                }

                NLA_FLAG => {
                    if attrlen > 0 {
                        break 'check;
                    }
                }

                NLA_SINT | NLA_UINT => {
                    if attrlen != 4 && attrlen != 8 {
                        set_err_attr_pol(extack, nla, pt, b"invalid attribute length\0");
                        return -EINVAL;
                    }
                }

                NLA_BITFIELD32 => {
                    if attrlen != 8 {
                        break 'check;
                    }

                    err = validate_nla_bitfield32(nla, p.mask32());
                    if err != 0 {
                        break 'check;
                    }
                }

                NLA_NUL_STRING | NLA_STRING => {
                    if p.type_ == NLA_NUL_STRING {
                        if p.len != 0 {
                            minlen = core::cmp::min(attrlen, p.len as c_int + 1);
                        } else {
                            minlen = attrlen;
                        }

                        // memchr(nla_data(nla), '\0', minlen) == NULL
                        if minlen == 0 || !has_nul(nla_data(nla), minlen) {
                            err = -EINVAL;
                            break 'check;
                        }
                        /* fallthrough */
                    }

                    if attrlen < 1 {
                        break 'check;
                    }

                    if p.len != 0 {
                        let buf = nla_data(nla);

                        if *buf.add(attrlen as usize - 1) == 0 {
                            attrlen -= 1;
                        }

                        if attrlen > p.len as c_int {
                            break 'check;
                        }
                    }
                }

                NLA_BINARY => {
                    if p.len != 0 && attrlen > p.len as c_int {
                        break 'check;
                    }
                }

                NLA_NESTED => {
                    /* a nested attributes is allowed to be empty; if its not,
                     * it must have a size of at least NLA_HDRLEN.
                     */
                    if attrlen != 0 {
                        if attrlen < NLA_HDRLEN {
                            break 'check;
                        }
                        if !p.ptr().is_null() {
                            err = nla_validate_parse(
                                nla_data(nla).cast(),
                                nla_len(nla),
                                p.len as c_int,
                                p.ptr().cast(),
                                validate,
                                extack,
                                core::ptr::null_mut(),
                                depth + 1,
                            );
                            if err < 0 {
                                /* return directly to preserve the inner error message/attribute pointer */
                                return err;
                            }
                        }
                    }
                }
                NLA_NESTED_ARRAY => {
                    if attrlen != 0 {
                        if attrlen < NLA_HDRLEN {
                            break 'check;
                        }
                        if !p.ptr().is_null() {
                            let e = nla_validate_array(
                                nla_data(nla).cast(),
                                nla_len(nla),
                                p.len as c_int,
                                p.ptr().cast(),
                                extack,
                                validate,
                                depth,
                            );
                            if e < 0 {
                                return e;
                            }
                        }
                    }
                }

                NLA_UNSPEC => {
                    if validate & NL_VALIDATE_UNSPEC != 0 {
                        set_err_attr_pol(extack, nla, core::ptr::null(), b"Unsupported attribute\0");
                        return -EINVAL;
                    }
                    if attrlen < p.len as c_int {
                        break 'check;
                    }
                }

                _ => {
                    if p.len != 0 {
                        minlen = p.len as c_int;
                    } else {
                        minlen = NLA_ATTR_MINLEN[p.type_ as usize] as c_int;
                    }

                    if attrlen < minlen {
                        break 'check;
                    }
                }
            }

            /* further validation */
            match p.validation_type {
                NLA_VALIDATE_NONE => {}
                NLA_VALIDATE_RANGE_PTR
                | NLA_VALIDATE_RANGE
                | NLA_VALIDATE_RANGE_WARN_TOO_LONG
                | NLA_VALIDATE_MIN
                | NLA_VALIDATE_MAX => {
                    err = nla_validate_int_range(pt, nla, extack, validate);
                    if err != 0 {
                        return err;
                    }
                }
                NLA_VALIDATE_MASK => {
                    err = nla_validate_mask(pt, nla, extack);
                    if err != 0 {
                        return err;
                    }
                }
                NLA_VALIDATE_FUNCTION => {
                    if !p.ptr().is_null() {
                        let f: ValidateFn = core::mem::transmute(p.ptr());
                        err = f(nla, extack);
                        if err != 0 {
                            return err;
                        }
                    }
                }
                _ => {}
            }

            return 0;
        }

        // out_err:
        set_err_attr_pol(extack, nla, pt, b"Attribute failed policy validation\0");
        err
    }
}

/// `memchr(p, '\0', n) != NULL`.
#[inline(always)]
unsafe fn has_nul(p: *const u8, n: c_int) -> bool {
    let mut i = 0;
    while i < n as usize {
        // SAFETY: `n` readable bytes (caller).
        if unsafe { *p.add(i) } == 0 {
            return true;
        }
        i += 1;
    }
    false
}

/// `__nla_validate_parse()`.
unsafe fn nla_validate_parse(
    head: *const Nlattr,
    len: c_int,
    maxtype: c_int,
    policy: *const NlaPolicy,
    validate: c_uint,
    extack: *mut NetlinkExtAck,
    tb: *mut *const Nlattr,
    depth: c_uint,
) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        if depth >= MAX_POLICY_RECURSION_DEPTH {
            set_err_msg(extack, b"allowed policy recursion depth exceeded\0");
            return -EINVAL;
        }

        if !tb.is_null() {
            core::ptr::write_bytes(tb, 0, maxtype.wrapping_add(1) as isize as usize);
        }

        let mut nla = head;
        let mut rem = len;
        while nla_ok(nla, rem) {
            let mut ty = nla_type(nla) as u16;

            if ty == 0 || ty as c_int > maxtype {
                if validate & NL_VALIDATE_MAXTYPE != 0 {
                    set_err_attr_pol(extack, nla, core::ptr::null(), b"Unknown attribute type\0");
                    return -EINVAL;
                }
                nla = nla_next(nla, &mut rem);
                continue;
            }
            ty = array_index_nospec(ty as u64, (maxtype + 1) as i64 as u64) as u16;
            if !policy.is_null() {
                let err = validate_nla(nla, maxtype, policy, validate, extack, depth);

                if err < 0 {
                    return err;
                }
            }

            if !tb.is_null() {
                *tb.add(ty as usize) = nla;
            }
            nla = nla_next(nla, &mut rem);
        }

        if rem > 0 {
            rust_nla_pr_leftover(rem);
            set_err_msg(extack, b"bytes leftover after parsing attributes\0");
            if validate & NL_VALIDATE_TRAILING != 0 {
                return -EINVAL;
            }
        }

        0
    }
}

// ---------------------------------------------------------------------------
// entry points called by nlattr_glue.c
// ---------------------------------------------------------------------------

/// `__nla_validate()`.
///
/// # Safety
/// As the C: `head..head+len` readable, `policy` null or `maxtype + 1` entries, `extack` null or valid.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_validate(
    head: *const Nlattr,
    len: c_int,
    maxtype: c_int,
    policy: *const NlaPolicy,
    validate: c_uint,
    extack: *mut NetlinkExtAck,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { nla_validate_parse(head, len, maxtype, policy, validate, extack, core::ptr::null_mut(), 0) }
}

/// `__nla_parse()`.
///
/// # Safety
/// As [`rust_nla_validate`], and `tb` has `maxtype + 1` entries.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_parse(
    tb: *mut *const Nlattr,
    maxtype: c_int,
    head: *const Nlattr,
    len: c_int,
    policy: *const NlaPolicy,
    validate: c_uint,
    extack: *mut NetlinkExtAck,
) -> c_int {
    // SAFETY: caller contract.
    unsafe { nla_validate_parse(head, len, maxtype, policy, validate, extack, tb, 0) }
}

/// `nla_policy_len()`.
///
/// # Safety
/// `p` has `n` entries.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_policy_len(p: *const NlaPolicy, n: c_int) -> c_int {
    let mut len: c_int = 0;
    let mut i = 0;
    while i < n {
        // SAFETY: caller contract.
        let p = unsafe { &*p.add(i as usize) };
        // nla_total_size(payload) = NLA_ALIGN(NLA_HDRLEN + payload)
        let total = |payload: c_int| (NLA_HDRLEN + payload + 3) & !3;
        if p.len != 0 {
            len = len.wrapping_add(total(p.len as c_int));
        } else if let Some(&l) = NLA_ATTR_LEN.get(p.type_ as usize).filter(|&&l| l != 0) {
            len = len.wrapping_add(total(l as c_int));
        } else if let Some(&l) = NLA_ATTR_MINLEN.get(p.type_ as usize).filter(|&&l| l != 0) {
            len = len.wrapping_add(total(l as c_int));
        }
        i += 1;
    }

    len
}

/// `nla_find()`.
///
/// # Safety
/// `head..head+len` readable.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_find(head: *const Nlattr, len: c_int, attrtype: c_int) -> *const Nlattr {
    // SAFETY: caller contract.
    unsafe {
        let mut nla = head;
        let mut rem = len;
        while nla_ok(nla, rem) {
            if nla_type(nla) == attrtype {
                return nla;
            }
            nla = nla_next(nla, &mut rem);
        }
        core::ptr::null()
    }
}

/// `nla_strscpy()` after the glue's `dstsize == 0 || WARN_ON_ONCE(dstsize > U16_MAX)` guard.
///
/// # Safety
/// `dst` has `dstsize` bytes; `nla` is a valid attribute.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_strscpy(dst: *mut u8, nla: *const Nlattr, dstsize: usize) -> isize {
    // SAFETY: caller contract.
    unsafe {
        let mut srclen = nla_len(nla) as usize;
        let src = nla_data(nla);
        let ret: isize;
        let len: usize;

        if srclen > 0 && *src.add(srclen - 1) == 0 {
            srclen -= 1;
        }

        if srclen >= dstsize {
            len = dstsize - 1;
            ret = -7; // -E2BIG
        } else {
            len = srclen;
            ret = len as isize;
        }

        core::ptr::copy_nonoverlapping(src, dst, len);
        /* Zero pad end of dst. */
        core::ptr::write_bytes(dst.add(len), 0, dstsize - len);

        ret
    }
}

/// `nla_memcpy()`.
///
/// # Safety
/// `dest` has `count` bytes; `src` is a valid attribute.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_memcpy(dest: *mut u8, src: *const Nlattr, count: c_int) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let minlen = core::cmp::min(count, nla_len(src));

        core::ptr::copy_nonoverlapping(nla_data(src), dest, minlen as usize);
        if count > minlen {
            core::ptr::write_bytes(dest.add(minlen as usize), 0, (count - minlen) as usize);
        }

        minlen
    }
}

/// `nla_memcmp()`.
///
/// # Safety
/// `data` has `size` bytes; `nla` is a valid attribute.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_memcmp(nla: *const Nlattr, data: *const u8, size: usize) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let mut d = (nla_len(nla) as usize).wrapping_sub(size) as c_int;

        if d == 0 {
            d = memcmp(nla_data(nla).cast(), data.cast(), size);
        }

        d
    }
}

/// `nla_strcmp()`.
///
/// # Safety
/// `str_` is a NUL-terminated string; `nla` is a valid attribute.
#[no_mangle]
pub unsafe extern "C" fn rust_nla_strcmp(nla: *const Nlattr, str_: *const u8) -> c_int {
    // SAFETY: caller contract.
    unsafe {
        let len = strlen(str_.cast()) as c_int;
        let buf = nla_data(nla);
        let mut attrlen = nla_len(nla);

        while attrlen > 0 && *buf.add(attrlen as usize - 1) == 0 {
            attrlen -= 1;
        }

        let mut d = attrlen - len;
        if d == 0 {
            d = memcmp(nla_data(nla).cast(), str_.cast(), len as usize);
        }

        d
    }
}
