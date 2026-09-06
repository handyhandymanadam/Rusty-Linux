// SPDX-License-Identifier: GPL-2.0
//! `lib/bug.c` -> `lib/bug_rs.rs`. `report_bug()`'s dispatch logic --
//! `bug_addr()`/`bug_get_file_line()`'s relative-pointer arithmetic,
//! `find_bug()`'s built-in-table search, the warning/once/done flag
//! bits, and `clear_once_table()` -- moved here as `report_bug_body()`.
//! `report_bug()` itself, the CONFIG_MODULES-entangled `struct module`
//! list machinery, and `generic_bug_clear_once()`'s own RCU-guarded walk
//! stay in `lib/bug.c` -- see that file's own header comment for the
//! full reasoning on both.
//!
//! # This file is reached from inside a trap handler
//!
//! `report_bug()` (`lib/bug.c`) is called directly from
//! `arch/x86/kernel/traps.c`'s invalid-opcode handler and
//! `arch/x86/mm/extable.c`'s exception-table fixup path -- the actual
//! trap target of every `BUG()`/`WARN()`'s `ud2` instruction in the
//! kernel. A panic reached from here is not an ordinary bug: it recurses
//! into the SAME trap-handling machinery this code exists to report on.
//! So, more than anywhere else this project has ported:
//!
//! - every arithmetic operation below that could plausibly see attacker-
//!   or corruption-influenced input uses `wrapping_*`, not bare
//!   operators -- CONFIG_RUST_OVERFLOW_CHECKS=y on both this project's
//!   configs (confirmed against `rig/uaccess-panic-check.sh`, which
//!   lists zero objects with a `panic_const_*` dependency after this
//!   file, same as before it), and lib/iomap.c's own hazard entry is the
//!   reason to check rather than assume;
//! - no slice/array indexing (all traversal here is raw-pointer
//!   arithmetic, matching the pristine C exactly, not a `[]` that could
//!   panic on an out-of-bounds `bug_entry` table);
//! - `file` is treated as possibly-NULL throughout, exactly where the
//!   pristine C does (`bug_get_file_line()` can report `file = NULL`
//!   under `!CONFIG_DEBUG_BUGVERBOSE`, not reachable on this project's
//!   two configs since both set it -- but the dispatch still branches on
//!   it, faithfully, rather than assuming it is always set).
//!
//! # `struct pt_regs`/`struct warn_args` are opaque
//!
//! Neither is ever read here -- both are only ever passed through by
//! pointer to `__warn()`. Same convention as `seq_buf_rs.rs`'s
//! `Path`/`SeqFileOpaque`: uninhabited `enum`s, no size, no layout, no
//! `Mirrors` claim.
//!
//! # No kabi pins in this file at all
//!
//! Nothing in `lib/bug.c` was ever `EXPORT_SYMBOL`'d -- every caller
//! (`traps.c`, `extable.c`, `kernel/kprobes.c`, `kernel/panic.c`) is
//! itself built-in. Unlike `buildid_rs.rs`/`iomap_rs.rs`, there is no
//! kabi-contract question here at all.

use core::ffi::{c_char, c_int, c_void};

/// Mirrors `struct bug_entry` (`include/asm-generic/bug.h`) in its
/// `CONFIG_GENERIC_BUG_RELATIVE_POINTERS=y` + `CONFIG_DEBUG_BUGVERBOSE=y`
/// shape -- the only shape either of this project's configs builds.
#[repr(C)]
pub struct BugEntry {
    bug_addr_disp: i32,
    file_disp: i32,
    line: u16,
    flags: u16,
}

const BUGFLAG_WARNING: u16 = 1 << 0;
const BUGFLAG_ONCE: u16 = 1 << 1;
const BUGFLAG_DONE: u16 = 1 << 2;
const BUGFLAG_NO_CUT_HERE: u16 = 1 << 3;

/// Opaque -- never read here, only passed through by pointer to
/// `__warn()`.
pub enum PtRegs {}
/// Opaque, same reasoning -- always `NULL` from this file's own call
/// site.
pub enum WarnArgs {}

/// Mirrors `enum bug_trap_type` (`include/linux/bug.h`).
#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum BugTrapType {
    /// Not a bug trap at all -- not a valid bug address, or no matching
    /// `.bug_table` entry.
    None = 0,
    /// A `WARN()`/`WARN_ON()` family trap.
    Warn = 1,
    /// A `BUG()`/`BUG_ON()` family trap.
    Bug = 2,
}

unsafe extern "C" {
    /// `arch/x86/kernel/traps.c` -- real, non-`static`, already-linkable.
    fn is_valid_bugaddr(addr: u64) -> c_int;
    /// `kernel/panic.c` -- real, substantial (register dump, module
    /// list, panic-on-warn, taint) infrastructure, not touched here.
    fn __warn(
        file: *const c_char,
        line: c_int,
        caller: *mut c_void,
        taint: u32,
        regs: *mut PtRegs,
        args: *mut WarnArgs,
    );
    fn _printk(fmt: *const c_char, ...) -> c_int;
    /// `lib/bug.c`'s own thunk -- see that file's header comment.
    fn rust_bug_disable_trace_on_warning();
    /// `lib/bug.c`, CONFIG_MODULES-entangled `struct module` list walk.
    fn module_find_bug(bugaddr: u64) -> *mut BugEntry;
}

/// `(unsigned long)&bug->bug_addr_disp + bug->bug_addr_disp` --
/// `wrapping_add_signed`, not `+`: this is a real, live 32-bit
/// displacement relative to its own field address, and while a
/// corrupted or adversarial `.bug_table` entry is not something this
/// project's own boot exercises, this function runs from inside a trap
/// handler, so it does not get to assume its input is well-formed the
/// way the rest of this project's ports could.
unsafe fn bug_addr(bug: *const BugEntry) -> u64 {
    unsafe {
        let field_addr = core::ptr::addr_of!((*bug).bug_addr_disp) as usize;
        field_addr.wrapping_add_signed((*bug).bug_addr_disp as isize) as u64
    }
}

/// Same relative-pointer treatment for `bug->file`. Returns a possibly-
/// null `file` pointer and the line number, matching
/// `bug_get_file_line()`'s two out-parameters.
#[no_mangle]
pub unsafe extern "C" fn bug_get_file_line(
    bug: *mut BugEntry,
    file: *mut *const c_char,
    line: *mut u32,
) {
    unsafe {
        let field_addr = core::ptr::addr_of!((*bug).file_disp) as usize;
        *file = field_addr.wrapping_add_signed((*bug).file_disp as isize) as *const c_char;
        *line = (*bug).line as u32;
    }
}

/// Searches the built-in `.bug_table` first, then falls back to the
/// (retained-C, RCU-guarded) module table search -- same order as the
/// pristine C.
#[no_mangle]
pub unsafe extern "C" fn find_bug(bugaddr: u64) -> *mut BugEntry {
    unsafe {
        extern "C" {
            #[link_name = "__start___bug_table"]
            static START_BUG_TABLE: BugEntry;
            #[link_name = "__stop___bug_table"]
            static STOP_BUG_TABLE: BugEntry;
        }
        let mut bug: *mut BugEntry = core::ptr::addr_of!(START_BUG_TABLE) as *mut BugEntry;
        let stop: *mut BugEntry = core::ptr::addr_of!(STOP_BUG_TABLE) as *mut BugEntry;
        while bug < stop {
            if bug_addr(bug) == bugaddr {
                return bug;
            }
            bug = bug.add(1);
        }
        module_find_bug(bugaddr)
    }
}

/// Clears `BUGFLAG_DONE` across one `bug_entry` range -- the built-in
/// table or one module's, called both ways by the retained C's
/// `generic_bug_clear_once()`. Pure, non-blocking: safe to call from
/// inside the RCU read-side critical section the module-range call sits
/// in.
#[no_mangle]
pub unsafe extern "C" fn generic_bug_clear_once_body(mut start: *mut BugEntry, end: *mut BugEntry) {
    unsafe {
        while start < end {
            (*start).flags &= !BUGFLAG_DONE;
            start = start.add(1);
        }
    }
}

/// `__report_bug()`'s body -- called by the retained C `report_bug()`,
/// already inside its `warn_rcu_enter()`/`warn_rcu_exit()` bracket.
#[no_mangle]
pub unsafe extern "C" fn report_bug_body(bugaddr: u64, regs: *mut PtRegs) -> BugTrapType {
    unsafe {
        if is_valid_bugaddr(bugaddr) == 0 {
            return BugTrapType::None;
        }

        let bug = find_bug(bugaddr);
        if bug.is_null() {
            return BugTrapType::None;
        }

        rust_bug_disable_trace_on_warning();

        let mut file: *const c_char = core::ptr::null();
        let mut line: u32 = 0;
        bug_get_file_line(bug, &mut file, &mut line);

        let flags = (*bug).flags;
        let warning = (flags & BUGFLAG_WARNING) != 0;
        let once = (flags & BUGFLAG_ONCE) != 0;
        let done = (flags & BUGFLAG_DONE) != 0;

        if warning && once {
            if done {
                return BugTrapType::Warn;
            }
            // Since this is the only store, concurrency is not an issue
            // (matches the pristine C's own comment).
            (*bug).flags |= BUGFLAG_DONE;
        }

        // BUG()/WARN_ON() families don't print a custom debug message
        // before triggering the exception handler, so the "cut here"
        // line goes out now. WARN() issues its own "cut here" before the
        // extra debugging message it writes before triggering the
        // handler.
        if (*bug).flags & BUGFLAG_NO_CUT_HERE == 0 {
            _printk(c"------------[ cut here ]------------\n".as_ptr());
        }

        if warning {
            // this is a WARN_ON rather than BUG/BUG_ON
            let taint = ((*bug).flags >> 8) as u32;
            __warn(file, line as c_int, bugaddr as *mut c_void, taint, regs, core::ptr::null_mut());
            return BugTrapType::Warn;
        }

        if !file.is_null() {
            _printk(c"\x012kernel BUG at %s:%u!\n".as_ptr(), file, line);
        } else {
            _printk(
                c"\x012Kernel BUG at %pB [verbose debug info unavailable]\n".as_ptr(),
                bugaddr as *const c_void,
            );
        }

        BugTrapType::Bug
    }
}
