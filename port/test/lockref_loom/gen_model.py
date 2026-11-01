#!/usr/bin/env python3
"""gen_model.py <lockref_rs.rs> <out.rs>: the model is the REAL loop text from lockref_rs.rs (Step, Outcome, cmpxchg_loop, the five
operations), with exactly three mechanical edits: the atomic type is loom's, the struct holds that atomic, and `#[no_mangle]` is dropped."""
import sys
s = open(sys.argv[1]).read()
a = s.index("/// Number of tries before falling back")
core = s[a:]
core = core.replace('let word = unsafe { AtomicU64::from_ptr(&raw mut (*lockref).lock_count) };',
                    'let word = unsafe { &(*lockref).lock_count };')
assert "from_ptr" not in core
core = core.replace('#[no_mangle]\n', '').replace('extern "C" ', '')
hdr = ("#![allow(dead_code)]\nuse loom::sync::atomic::{AtomicU64, Ordering};\nuse std::ffi::c_int;\n"
       "pub struct Lockref { pub lock_count: AtomicU64 }\n")
open(sys.argv[2], "w").write(hdr + core)
