// SPDX-License-Identifier: GPL-2.0-or-later

//! ASN.1 BER/DER/CER bytecode-interpreter decoder -- the Rust behind
//! `lib/asn1_decoder.c`.
//!
//! Ported from `lib/asn1_decoder.c` (6.18.49), Copyright (C) 2012, Red Hat,
//! Inc., written by David Howells.
//!
//! Replaces: lib/asn1_decoder.c
//!
//! # What this is
//!
//! `asn1_ber_decoder()` interprets a small bytecode language emitted at
//! build time by `scripts/asn1_compiler.c` from a `.asn1` grammar file
//! (`crypto/asymmetric_keys/x509.asn1`, `crypto/rsapubkey.asn1`, etc.) --
//! the grammar compiles to a `machine[]` byte array plus an `actions[]`
//! function-pointer table, both baked into the kernel image, and this
//! function walks `machine[]` matching tags out of caller-supplied,
//! UNTRUSTED `data[]` (an X.509 certificate, an RSA key blob, ...),
//! calling into `actions[]` when the grammar says a field of interest was
//! found. `machine[]`/`actions[]` are trusted (compiler-generated, never
//! attacker-influenced); `data[]` is not.
//!
//! # Every error path in the C converges on one return, so this has no
//! # goto-shaped state machine to reproduce for them
//!
//! The C's `data_overrun_error`/`machine_overrun_error`/
//! `jump_stack_overflow`/`cons_stack_overflow`/`tag_mismatch`/etc. labels
//! each set a `const char *errmsg` for a `pr_debug()` line, then all fall
//! into one shared `error:` label that unconditionally returns
//! `-EBADMSG`. Dropping the debug print (as other diagnostic-only prints
//! have been dropped elsewhere in this port) collapses every one of those
//! sites to a plain `return -EBADMSG;` -- there is no shared control-flow
//! state left to reproduce, just the condition that triggers each one.
//! `asn1_find_indefinite_length()`'s five error labels collapse the same
//! way, to `*_dp = dp; return -1;`.
//!
//! # One real, deliberate divergence from the main decoder: kept, not fixed
//!
//! `asn1_find_indefinite_length()`'s long-form-length-octet-count check is
//! `n > sizeof(len) - 1` (7, since `len` is a 64-bit `size_t`) while the
//! main decoder's equivalent check is `n > 2` (16-bit lengths only, tying
//! into `datalen`'s own 65535-byte cap). Two different limits for two
//! different reasons in the same upstream file -- reproduced exactly, not
//! reconciled, since this is the C's own real behavior on the rare
//! indefinite-length-primitive-under-indefinite-length-wrapper path, not
//! a port bug.
//!
//! # A bounds check the C does not have, and does not need
//!
//! `op = machine[pc]` is a raw byte from TRUSTED, compiler-generated
//! bytecode -- never attacker-influenced -- so the C indexes
//! `asn1_op_lengths[op]` (a 0x29-entry table) without checking `op` is
//! actually a valid opcode; the compiler never emits anything else. Rust
//! has no such "trust the byte, it's really our own compiler's output"
//! escape hatch for an array index computed from a value read out of a
//! `*const u8`, so this looks it up via `.get()` and returns `-EBADMSG`
//! (matching the "Found reserved opcode" path the C's `switch`'s
//! unreachable `default` arm would eventually have produced anyway) on
//! any byte the table doesn't cover. Never taken by any real, compiler-
//! generated `machine[]` -- a strictly safer superset of the C's actual
//! behavior, not a behavioral change for any input that can really occur.
//!
//! # No `&`/`&mut` over any of `data`/`machine`/`actions`/`context`
//!
//! All four are caller-owned buffers this function does not know the
//! full extent or exclusivity of beyond what its own contract promises;
//! every access goes through raw pointer arithmetic, matching this
//! project's established discipline for FFI buffers of unknown
//! aliasing (`logs/porting-hazards.md`'s aliasing item), even though
//! nothing here is expected to alias anything else in practice.
//!
//! # Fallthrough, reproduced as a shared condition rather than shared code
//!
//! C's `case ASN1_OP_END_SET: ... fallthrough; case ASN1_OP_END_SEQ: ...`
//! (SET variants add one precondition check, then run the SAME body as
//! SEQ) and `case ASN1_OP_MAYBE_ACT: ...; fallthrough; case ASN1_OP_ACT:
//! ...` become single match arms covering both opcodes, with the extra
//! precondition made an explicit `if` gated on which opcode it actually
//! was -- there is no separate code path to lose sync with the other.

#![allow(non_upper_case_globals)]

use core::ffi::{c_int, c_void};
use core::mem::size_of;

/// `asn1_action_t`, `include/linux/asn1_ber_bytecode.h`.
pub type Asn1ActionT =
    unsafe extern "C" fn(*mut c_void, usize, u8, *const c_void, usize) -> c_int;

/// Mirrors `struct asn1_decoder`, `include/linux/asn1_ber_bytecode.h`.
/// 24 bytes: three pointer-or-size_t fields, no padding.
#[repr(C)]
pub struct Asn1Decoder {
    /// The compiled bytecode program.
    pub machine: *const u8,
    /// Length of `machine`, in bytes.
    pub machlen: usize,
    /// Action callbacks, indexed by the bytecode's own action numbers.
    pub actions: *const Asn1ActionT,
}

const EBADMSG: c_int = 74;
const EMSGSIZE: c_int = 90;

// enum asn1_opcode, include/linux/asn1_ber_bytecode.h. ASN1_OP_MATCH__JUMP
// is kept for parity with the header even though, like the C, nothing
// here tests it directly -- MATCH_JUMP-family opcodes are matched by
// name instead.
const ASN1_OP_MATCH__SKIP: u8 = 0x01;
const ASN1_OP_MATCH__ACT: u8 = 0x02;
#[allow(dead_code)]
const ASN1_OP_MATCH__JUMP: u8 = 0x04;
const ASN1_OP_MATCH__ANY: u8 = 0x08;
const ASN1_OP_MATCH__COND: u8 = 0x10;

const ASN1_OP_MATCH: u8 = 0x00;
const ASN1_OP_MATCH_OR_SKIP: u8 = 0x01;
const ASN1_OP_MATCH_ACT: u8 = 0x02;
const ASN1_OP_MATCH_ACT_OR_SKIP: u8 = 0x03;
const ASN1_OP_MATCH_JUMP: u8 = 0x04;
const ASN1_OP_MATCH_JUMP_OR_SKIP: u8 = 0x05;
const ASN1_OP_MATCH_ANY: u8 = 0x08;
const ASN1_OP_MATCH_ANY_OR_SKIP: u8 = 0x09;
const ASN1_OP_MATCH_ANY_ACT: u8 = 0x0a;
const ASN1_OP_MATCH_ANY_ACT_OR_SKIP: u8 = 0x0b;

const ASN1_OP_COND_MATCH_OR_SKIP: u8 = 0x11;
const ASN1_OP_COND_MATCH_ACT_OR_SKIP: u8 = 0x13;
const ASN1_OP_COND_MATCH_JUMP_OR_SKIP: u8 = 0x15;
const ASN1_OP_COND_MATCH_ANY: u8 = 0x18;
const ASN1_OP_COND_MATCH_ANY_OR_SKIP: u8 = 0x19;
const ASN1_OP_COND_MATCH_ANY_ACT: u8 = 0x1a;
const ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP: u8 = 0x1b;

const ASN1_OP__MATCHES_TAG: u8 = ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP;

const ASN1_OP_COND_FAIL: u8 = 0x1c;
const ASN1_OP_COMPLETE: u8 = 0x1d;
const ASN1_OP_ACT: u8 = 0x1e;
const ASN1_OP_MAYBE_ACT: u8 = 0x1f;

const ASN1_OP_END_SEQ: u8 = 0x20;
const ASN1_OP_END_SET: u8 = 0x21;
const ASN1_OP_END_SEQ_OF: u8 = 0x22;
const ASN1_OP_END_SET_OF: u8 = 0x23;
const ASN1_OP_END_SEQ_ACT: u8 = 0x24;
const ASN1_OP_END_SET_ACT: u8 = 0x25;
const ASN1_OP_END_SEQ_OF_ACT: u8 = 0x26;
const ASN1_OP_END_SET_OF_ACT: u8 = 0x27;
const ASN1_OP_END__OF: u8 = 0x02;
const ASN1_OP_END__ACT: u8 = 0x04;

const ASN1_OP_RETURN: u8 = 0x28;
const ASN1_OP__NR: usize = 0x29;

// include/linux/asn1.h.
const ASN1_PRIM: u8 = 0;
const ASN1_CONS_BIT: u8 = 0x20;
const ASN1_EOC: u8 = 0;
const ASN1_LONG_TAG: u8 = 31;
const ASN1_INDEFINITE_LENGTH: u8 = 0x80;

// Flags, local to the decoder.
const FLAG_INDEFINITE_LENGTH: u8 = 0x01;
const FLAG_MATCHED: u8 = 0x02;
const FLAG_LAST_MATCHED: u8 = 0x04;
const FLAG_CONS: u8 = 0x20;

const NR_CONS_STACK: usize = 10;
const NR_JUMP_STACK: usize = 10;

/// `asn1_op_lengths[]`. Bytes consumed by each opcode: itself, plus tag/
/// jump-target/action operand bytes as applicable.
const ASN1_OP_LENGTHS: [u8; ASN1_OP__NR] = {
    let mut t = [0u8; ASN1_OP__NR];
    t[ASN1_OP_MATCH as usize] = 1 + 1;
    t[ASN1_OP_MATCH_OR_SKIP as usize] = 1 + 1;
    t[ASN1_OP_MATCH_ACT as usize] = 1 + 1 + 1;
    t[ASN1_OP_MATCH_ACT_OR_SKIP as usize] = 1 + 1 + 1;
    t[ASN1_OP_MATCH_JUMP as usize] = 1 + 1 + 1;
    t[ASN1_OP_MATCH_JUMP_OR_SKIP as usize] = 1 + 1 + 1;
    t[ASN1_OP_MATCH_ANY as usize] = 1;
    t[ASN1_OP_MATCH_ANY_OR_SKIP as usize] = 1;
    t[ASN1_OP_MATCH_ANY_ACT as usize] = 1 + 1;
    t[ASN1_OP_MATCH_ANY_ACT_OR_SKIP as usize] = 1 + 1;
    t[ASN1_OP_COND_MATCH_OR_SKIP as usize] = 1 + 1;
    t[ASN1_OP_COND_MATCH_ACT_OR_SKIP as usize] = 1 + 1 + 1;
    t[ASN1_OP_COND_MATCH_JUMP_OR_SKIP as usize] = 1 + 1 + 1;
    t[ASN1_OP_COND_MATCH_ANY as usize] = 1;
    t[ASN1_OP_COND_MATCH_ANY_OR_SKIP as usize] = 1;
    t[ASN1_OP_COND_MATCH_ANY_ACT as usize] = 1 + 1;
    t[ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP as usize] = 1 + 1;
    t[ASN1_OP_COND_FAIL as usize] = 1;
    t[ASN1_OP_COMPLETE as usize] = 1;
    t[ASN1_OP_ACT as usize] = 1 + 1;
    t[ASN1_OP_MAYBE_ACT as usize] = 1 + 1;
    t[ASN1_OP_RETURN as usize] = 1;
    t[ASN1_OP_END_SEQ as usize] = 1;
    t[ASN1_OP_END_SEQ_OF as usize] = 1 + 1;
    t[ASN1_OP_END_SET as usize] = 1;
    t[ASN1_OP_END_SET_OF as usize] = 1 + 1;
    t[ASN1_OP_END_SEQ_ACT as usize] = 1 + 1;
    t[ASN1_OP_END_SEQ_OF_ACT as usize] = 1 + 1 + 1;
    t[ASN1_OP_END_SET_ACT as usize] = 1 + 1;
    t[ASN1_OP_END_SET_OF_ACT as usize] = 1 + 1 + 1;
    t
};

/// `asn1_find_indefinite_length()`. Scans forward from `*dp` to find where
/// an indefinite-length-encoded value's content actually ends.
///
/// # Safety
/// `data` must be readable for `datalen` bytes; `*dp <= datalen` on entry.
unsafe fn asn1_find_indefinite_length(
    data: *const u8,
    datalen: usize,
    dp_inout: &mut usize,
    len_out: &mut usize,
) -> i32 {
    let start = *dp_inout;
    let mut dp = start;
    let mut indef_level: i32 = 1;

    loop {
        if datalen.wrapping_sub(dp) < 2 {
            // missing_eoc (dp == datalen) or data_overrun_error -- same
            // return either way, since the errmsg was diagnostic only.
            *dp_inout = dp;
            return -1;
        }
        // SAFETY: `datalen - dp >= 2` just checked, `data` readable for
        // `datalen` bytes per this function's contract.
        let tag = unsafe { *data.add(dp) };
        dp += 1;

        if tag == ASN1_EOC {
            // SAFETY: as above, one more byte available.
            let eoc_len = unsafe { *data.add(dp) };
            dp += 1;
            if eoc_len != 0 {
                *dp_inout = dp;
                return -1; // invalid_eoc
            }
            indef_level -= 1;
            if indef_level <= 0 {
                *len_out = dp - start;
                *dp_inout = dp;
                return 0;
            }
            continue;
        }

        if (tag & 0x1f) == ASN1_LONG_TAG {
            loop {
                if datalen.wrapping_sub(dp) < 2 {
                    *dp_inout = dp;
                    return -1; // data_overrun_error
                }
                // SAFETY: as above.
                let tmp = unsafe { *data.add(dp) };
                dp += 1;
                if tmp & 0x80 == 0 {
                    break;
                }
            }
        }

        // SAFETY: bounds already ensured at least one more byte is
        // available on every path reaching here.
        let mut len = unsafe { *data.add(dp) } as usize;
        dp += 1;

        if len > 0x7f {
            if len == ASN1_INDEFINITE_LENGTH as usize {
                if (tag & ASN1_CONS_BIT) == (ASN1_PRIM << 5) {
                    *dp_inout = dp;
                    return -1; // indefinite_len_primitive
                }
                indef_level += 1;
                continue;
            }

            let n = len - 0x80;
            if n > (size_of::<usize>() - 1) {
                *dp_inout = dp;
                return -1; // length_too_long -- note: 7, not 2, on this path
            }
            if n > datalen.wrapping_sub(dp) {
                *dp_inout = dp;
                return -1; // data_overrun_error
            }
            len = 0;
            for _ in 0..n {
                // SAFETY: `n <= datalen - dp` just checked.
                len = (len << 8) | unsafe { *data.add(dp) } as usize;
                dp += 1;
            }
        }
        if len > datalen.wrapping_sub(dp) {
            *dp_inout = dp;
            return -1; // data_overrun_error
        }
        dp += len;
    }
}

/// `asn1_ber_decoder()`: interpret `decoder`'s bytecode against `data`,
/// calling into `decoder.actions` on marked tags.
///
/// # Safety
/// `decoder` must be valid; `decoder.machine` readable for
/// `decoder.machlen` bytes; `decoder.actions` readable for as many
/// entries as the bytecode's highest action index requires; `data`
/// readable for `datalen` bytes; every function pointer in `actions`
/// must be safe to call with `(context, hdrlen, tag, value_ptr, vlen)`
/// where `value_ptr` points somewhere inside `data`.
#[no_mangle]
pub unsafe extern "C" fn asn1_ber_decoder(
    decoder: *const Asn1Decoder,
    context: *mut c_void,
    data: *const u8,
    mut datalen: usize,
) -> c_int {
    // SAFETY: caller guarantees `decoder` valid.
    let machine = unsafe { (*decoder).machine };
    let actions = unsafe { (*decoder).actions };
    let machlen = unsafe { (*decoder).machlen };

    let mut tag: u8 = 0;
    let mut csp: u8 = 0;
    let mut jsp: u8 = 0;
    let mut hdr: u8 = 0;
    let mut pc: usize = 0;
    let mut dp: usize = 0;
    let mut tdp: usize = 0;
    let mut len: usize = 0;
    let mut flags: u8 = 0;

    let mut cons_dp_stack = [0u16; NR_CONS_STACK];
    let mut cons_datalen_stack = [0u16; NR_CONS_STACK];
    let mut cons_hdrlen_stack = [0u8; NR_CONS_STACK];
    let mut jump_stack = [0u8; NR_JUMP_STACK];

    if datalen > 65535 {
        return -EMSGSIZE;
    }

    'next_op: loop {
        if pc >= machlen {
            return -EBADMSG; // machine_overrun_error
        }
        // SAFETY: `pc < machlen` just checked; caller guarantees `machine`
        // readable for `machlen` bytes.
        let op = unsafe { *machine.add(pc) };
        // Deliberately safer than the C here -- see the module doc's
        // "A bounds check the C does not have" section. Never taken by
        // real, compiler-generated bytecode.
        let Some(&op_len) = ASN1_OP_LENGTHS.get(op as usize) else {
            return -EBADMSG;
        };
        if pc + op_len as usize > machlen {
            return -EBADMSG; // machine_overrun_error
        }

        if op <= ASN1_OP__MATCHES_TAG {
            // Skip conditional matches if possible.
            if (op & ASN1_OP_MATCH__COND != 0 && flags & FLAG_MATCHED != 0)
                || (op & ASN1_OP_MATCH__SKIP != 0 && dp == datalen)
            {
                flags &= !FLAG_LAST_MATCHED;
                pc += op_len as usize;
                continue 'next_op;
            }

            flags = 0;
            hdr = 2;

            if datalen.wrapping_sub(dp) < 2 {
                return -EBADMSG; // data_overrun_error
            }
            // SAFETY: caller guarantees `data` readable for `datalen`
            // bytes; `dp < datalen - 1` just checked.
            tag = unsafe { *data.add(dp) };
            dp += 1;
            if (tag & 0x1f) == ASN1_LONG_TAG {
                return -EBADMSG; // long_tag_not_supported
            }

            if op & ASN1_OP_MATCH__ANY == 0 {
                // SAFETY: `pc + op_len <= machlen` already checked, and
                // every opcode <= ASN1_OP__MATCHES_TAG without
                // ASN1_OP_MATCH__ANY has a tag operand at pc+1.
                let optag = unsafe { *machine.add(pc + 1) };
                flags |= optag & FLAG_CONS;

                let tmp = (optag ^ tag) & !(optag & ASN1_CONS_BIT);
                if tmp != 0 {
                    if op & ASN1_OP_MATCH__SKIP != 0 {
                        pc += op_len as usize;
                        dp -= 1;
                        continue 'next_op;
                    }
                    return -EBADMSG; // tag_mismatch
                }
            }
            flags |= FLAG_MATCHED;

            // SAFETY: `dp < datalen` here (one byte was consumed above,
            // and `datalen - dp >= 2` before that consumption).
            len = unsafe { *data.add(dp) } as usize;
            dp += 1;
            if len > 0x7f {
                if len == ASN1_INDEFINITE_LENGTH as usize {
                    if tag & ASN1_CONS_BIT == 0 {
                        return -EBADMSG; // indefinite_len_primitive
                    }
                    flags |= FLAG_INDEFINITE_LENGTH;
                    if 2 > datalen.wrapping_sub(dp) {
                        return -EBADMSG; // data_overrun_error
                    }
                } else {
                    // `len` is guaranteed in 0x81..=0xff here (0x80 exactly
                    // is the indefinite-length case, handled above), so
                    // this subtraction never wraps.
                    let n = len - 0x80;
                    if n > 2 {
                        return -EBADMSG; // length_too_long
                    }
                    if n > datalen.wrapping_sub(dp) {
                        return -EBADMSG; // data_overrun_error
                    }
                    hdr += n as u8;
                    len = 0;
                    for _ in 0..n {
                        // SAFETY: `n <= datalen - dp` just checked.
                        len = (len << 8) | unsafe { *data.add(dp) } as usize;
                        dp += 1;
                    }
                    if len > datalen.wrapping_sub(dp) {
                        return -EBADMSG; // data_overrun_error
                    }
                }
            } else if len > datalen.wrapping_sub(dp) {
                return -EBADMSG; // data_overrun_error
            }

            if flags & FLAG_CONS != 0 {
                if csp as usize >= NR_CONS_STACK {
                    return -EBADMSG; // cons_stack_overflow
                }
                cons_dp_stack[csp as usize] = dp as u16;
                cons_hdrlen_stack[csp as usize] = hdr;
                if flags & FLAG_INDEFINITE_LENGTH == 0 {
                    cons_datalen_stack[csp as usize] = datalen as u16;
                    // datalen is bounded to <= 65535 above and dp+len
                    // never exceeds the original datalen on any path
                    // that reaches here (both were just bounds-checked
                    // against it), so this narrowing matches the C's own
                    // `unsigned short cons_dp_stack[]` exactly, not a
                    // truncation bug.
                    datalen = dp + len;
                } else {
                    cons_datalen_stack[csp as usize] = 0;
                }
                csp += 1;
            }
            tdp = dp;
        }

        match op {
            ASN1_OP_MATCH
            | ASN1_OP_MATCH_OR_SKIP
            | ASN1_OP_MATCH_ACT
            | ASN1_OP_MATCH_ACT_OR_SKIP
            | ASN1_OP_MATCH_ANY
            | ASN1_OP_MATCH_ANY_OR_SKIP
            | ASN1_OP_MATCH_ANY_ACT
            | ASN1_OP_MATCH_ANY_ACT_OR_SKIP
            | ASN1_OP_COND_MATCH_OR_SKIP
            | ASN1_OP_COND_MATCH_ACT_OR_SKIP
            | ASN1_OP_COND_MATCH_ANY
            | ASN1_OP_COND_MATCH_ANY_OR_SKIP
            | ASN1_OP_COND_MATCH_ANY_ACT
            | ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP => {
                if flags & FLAG_CONS == 0 && flags & FLAG_INDEFINITE_LENGTH != 0 {
                    let mut tmp = dp;
                    // SAFETY: caller guarantees `data` readable for
                    // `datalen` bytes; `tmp <= datalen` here.
                    let ret =
                        unsafe { asn1_find_indefinite_length(data, datalen, &mut tmp, &mut len) };
                    if ret < 0 {
                        return -EBADMSG;
                    }
                }

                if op & ASN1_OP_MATCH__ACT != 0 {
                    let act = if op & ASN1_OP_MATCH__ANY != 0 {
                        // SAFETY: bounds already checked via op_len/machlen.
                        unsafe { *machine.add(pc + 1) }
                    } else {
                        // SAFETY: as above.
                        unsafe { *machine.add(pc + 2) }
                    };
                    // SAFETY: caller guarantees `actions` has an entry for
                    // every action index the bytecode references, and
                    // that entry is safe to call with these arguments.
                    let f = unsafe { *actions.add(act as usize) };
                    // SAFETY: `data + dp` is in-bounds per this function's
                    // own bounds-checked `dp`/`len`.
                    let ret = unsafe { f(context, hdr as usize, tag, data.add(dp).cast(), len) };
                    if ret < 0 {
                        return ret;
                    }
                }

                if flags & FLAG_CONS == 0 {
                    dp += len;
                }
                pc += op_len as usize;
                continue 'next_op;
            }

            ASN1_OP_MATCH_JUMP | ASN1_OP_MATCH_JUMP_OR_SKIP | ASN1_OP_COND_MATCH_JUMP_OR_SKIP => {
                if jsp as usize == NR_JUMP_STACK {
                    return -EBADMSG; // jump_stack_overflow
                }
                jump_stack[jsp as usize] = (pc + op_len as usize) as u8;
                jsp += 1;
                // SAFETY: bounds already checked via op_len/machlen.
                pc = unsafe { *machine.add(pc + 2) } as usize;
                continue 'next_op;
            }

            ASN1_OP_COND_FAIL => {
                if flags & FLAG_MATCHED == 0 {
                    return -EBADMSG; // tag_mismatch
                }
                pc += op_len as usize;
                continue 'next_op;
            }

            ASN1_OP_COMPLETE => {
                if jsp != 0 || csp != 0 {
                    return -EBADMSG; // "Stacks not empty at completion"
                }
                return 0;
            }

            ASN1_OP_END_SEQ
            | ASN1_OP_END_SET
            | ASN1_OP_END_SEQ_OF
            | ASN1_OP_END_SET_OF
            | ASN1_OP_END_SEQ_ACT
            | ASN1_OP_END_SET_ACT
            | ASN1_OP_END_SEQ_OF_ACT
            | ASN1_OP_END_SET_OF_ACT => {
                if (op == ASN1_OP_END_SET || op == ASN1_OP_END_SET_ACT) && flags & FLAG_MATCHED == 0
                {
                    return -EBADMSG; // tag_mismatch
                }
                if csp == 0 {
                    return -EBADMSG; // cons_stack_underflow
                }
                csp -= 1;
                tdp = cons_dp_stack[csp as usize] as usize;
                hdr = cons_hdrlen_stack[csp as usize];
                len = datalen;
                datalen = cons_datalen_stack[csp as usize] as usize;

                if datalen == 0 {
                    datalen = len;
                    if datalen.wrapping_sub(dp) < 2 {
                        return -EBADMSG; // data_overrun_error
                    }
                    // SAFETY: caller guarantees `data` readable for
                    // `datalen` bytes; bounds just checked.
                    if unsafe { *data.add(dp) } != 0 {
                        dp += 1;
                        if op & ASN1_OP_END__OF != 0 {
                            dp -= 1;
                            csp += 1;
                            // SAFETY: bounds already checked via
                            // op_len/machlen.
                            pc = unsafe { *machine.add(pc + 1) } as usize;
                            continue 'next_op;
                        }
                        return -EBADMSG; // missing_eoc
                    }
                    dp += 1;
                    // SAFETY: as above.
                    if unsafe { *data.add(dp) } != 0 {
                        return -EBADMSG; // invalid_eoc
                    }
                    dp += 1;
                    len = dp - tdp - 2;
                } else {
                    if dp < len && op & ASN1_OP_END__OF != 0 {
                        datalen = len;
                        csp += 1;
                        // SAFETY: bounds already checked via op_len/machlen.
                        pc = unsafe { *machine.add(pc + 1) } as usize;
                        continue 'next_op;
                    }
                    if dp != len {
                        return -EBADMSG; // cons_length_error
                    }
                    len -= tdp;
                }

                if op & ASN1_OP_END__ACT != 0 {
                    let act = if op & ASN1_OP_END__OF != 0 {
                        // SAFETY: bounds already checked via op_len/machlen.
                        unsafe { *machine.add(pc + 2) }
                    } else {
                        // SAFETY: as above.
                        unsafe { *machine.add(pc + 1) }
                    };
                    // SAFETY: caller guarantees `actions` has an entry for
                    // every action index the bytecode references.
                    let f = unsafe { *actions.add(act as usize) };
                    // SAFETY: `data + tdp` is in-bounds -- `tdp` was
                    // recorded from a previously bounds-checked `dp`.
                    let ret = unsafe { f(context, hdr as usize, 0, data.add(tdp).cast(), len) };
                    if ret < 0 {
                        return ret;
                    }
                }
                pc += op_len as usize;
                continue 'next_op;
            }

            ASN1_OP_MAYBE_ACT | ASN1_OP_ACT => {
                if op == ASN1_OP_MAYBE_ACT && flags & FLAG_LAST_MATCHED == 0 {
                    pc += op_len as usize;
                    continue 'next_op;
                }
                // SAFETY: bounds already checked via op_len/machlen.
                let act = unsafe { *machine.add(pc + 1) };
                // SAFETY: caller guarantees `actions` has an entry for
                // every action index the bytecode references.
                let f = unsafe { *actions.add(act as usize) };
                // SAFETY: `data + tdp` is in-bounds -- `tdp` was recorded
                // from a previously bounds-checked `dp`.
                let ret = unsafe { f(context, hdr as usize, tag, data.add(tdp).cast(), len) };
                if ret < 0 {
                    return ret;
                }
                pc += op_len as usize;
                continue 'next_op;
            }

            ASN1_OP_RETURN => {
                if jsp == 0 {
                    return -EBADMSG; // jump_stack_underflow
                }
                jsp -= 1;
                pc = jump_stack[jsp as usize] as usize;
                flags |= FLAG_MATCHED | FLAG_LAST_MATCHED;
                continue 'next_op;
            }

            _ => return -EBADMSG, // "Found reserved opcode"
        }
    }
}

// `s#asn1_decoder`'s own type-string rule, registered standalone (see
// dynamic_queue_limits_rs.rs's identical `s#dql` rule and its own doc
// comment for why this is needed despite other C translation units --
// crypto/rsapubkey.asn1.c, x509.asn1.c, pkcs7.asn1.c -- also declaring
// `struct asn1_decoder` variables in this same vmlinux link).
//
// UNLIKE `s#dql`, one registration was not enough: every `t#name`
// backreference inside a MANUALLY registered rule needs its OWN manual
// rule too -- gendwarfksyms does not fall back to resolving a hand-
// injected rule's backreferences against the rest of the vmlinux's real
// DWARF the way it resolves a name appearing directly in a function
// signature. So the full chain `kabi-pin.sh --capture` produced is
// registered here, not just the struct itself.
kernel::kabi_rule!(
    "type_string",
    "s#asn1_decoder",
    "structure_type asn1_decoder { member pointer_type { const_type { base_type unsigned char byte_size(1) encoding(8) } } machine data_member_location(0) , member t#size_t machlen data_member_location(8) , member pointer_type { const_type { t#asn1_action_t } } actions data_member_location(16) } byte_size(24)"
);
kernel::kabi_rule!(
    "type_string",
    "t#asn1_action_t",
    "typedef_type asn1_action_t { pointer_type { subroutine_type ( formal_parameter pointer_type { base_type void } , formal_parameter t#size_t , formal_parameter base_type unsigned char byte_size(1) encoding(8) , formal_parameter pointer_type { const_type { base_type void } } , formal_parameter t#size_t ) -> base_type int byte_size(4) encoding(5) } }"
);
kernel::kabi_rule!(
    "type_string",
    "t#size_t",
    "typedef_type size_t { t#__kernel_size_t }"
);
kernel::kabi_rule!(
    "type_string",
    "t#__kernel_size_t",
    "typedef_type __kernel_size_t { t#__kernel_ulong_t }"
);
kernel::kabi_rule!(
    "type_string",
    "t#__kernel_ulong_t",
    "typedef_type __kernel_ulong_t { base_type unsigned long byte_size(8) encoding(7) }"
);

kernel::kabi_export! {
    asn1_ber_decoder,
    license = "GPL",
    namespace = "",
    contract = "subprogram ( formal_parameter pointer_type { const_type { s#asn1_decoder } } decoder , formal_parameter pointer_type { base_type void } context , formal_parameter pointer_type { const_type { base_type unsigned char byte_size(1) encoding(8) } } data , formal_parameter t#size_t datalen ) -> base_type int byte_size(4) encoding(5)",
}
