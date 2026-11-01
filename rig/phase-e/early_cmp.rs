// Userspace differential: main_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C of do_early_param / parse_early_options /
// parse_early_param (early_ref.c) on the real C parse_args (params_ref.c). Random `__setup` tables (24 entries: names with dashes /
// underscores, early or not, results 0 / non-zero), random boot command lines (quotes, `--`, unknown, > 2047 bytes so strscpy truncates),
// each run twice in a row (the second call must do nothing). Compared: the ordered log of setup_func calls (index, value) and every printk.
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs)]
#[path = "MAINRS"]
mod h;
use std::cell::RefCell;
use std::ffi::{c_char, c_void};
extern "C" {
    fn e_table() -> *mut u8;
    fn e_cmdline() -> *mut u8;
    fn e_sf(i: i32) -> *const c_void;
    fn e_c_early();
    fn e_reset();
}
#[derive(PartialEq, Debug, Clone)]
enum Ev { Msg(Vec<u8>), Set(i32, Option<Vec<u8>>) }
thread_local! { static LOG: RefCell<Vec<Ev>> = RefCell::new(Vec::new()); static RET: RefCell<Vec<i32>> = RefCell::new(vec![0; 24]); }
#[no_mangle] pub extern "C" fn log_event(_k: i32, _a: i64, _b: i64) {}
#[no_mangle] pub extern "C" fn log_msg(t: *const u8, n: i32) { LOG.with(|l| l.borrow_mut().push(Ev::Msg(unsafe { std::slice::from_raw_parts(t, n as usize).to_vec() }))); }
#[no_mangle] pub extern "C" fn setup_cb(idx: i32, val: *mut c_char) -> i32 {
    LOG.with(|l| l.borrow_mut().push(Ev::Set(idx, if val.is_null() { None } else { Some(unsafe { std::ffi::CStr::from_ptr(val) }.to_bytes().to_vec()) })));
    RET.with(|r| r.borrow()[idx as usize])
}
struct Rng(u64);
impl Rng { fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x } fn below(&mut self, n: u64) -> u64 { self.next() % n } }
fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let mut r = Rng(0x9e3779b97f4a7c15);
    let pool: Vec<&[u8]> = vec![b"foo", b"bar-baz", b"bar_baz", b"console", b"mem", b"earlycon", b"x", b"a-b-c", b"noapic", b"root", b"early-param", b"", b"q"];
    let (mut tot, mut sets, mut mal, mut trunc) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..n {
        // table: names live in one arena, entries pointing into it
        let mut arena: Vec<Vec<u8>> = vec![];
        let mut ents: Vec<(usize, bool, i32)> = vec![]; // (name index or usize::MAX, early, result)
        for _ in 0..24 {
            if r.below(5) == 0 { ents.push((usize::MAX, false, 0)); continue; }
            let mut nm = pool[r.below(pool.len() as u64) as usize].to_vec(); if r.below(3) == 0 { for c in nm.iter_mut() { if *c == b'-' { *c = b'_' } else if *c == b'_' { *c = b'-' } } }
            nm.push(0); arena.push(nm); ents.push((arena.len() - 1, r.below(3) != 0, if r.below(4) == 0 { (r.below(5) as i32) - 2 } else { 0 }));
        }
        let mut line: Vec<u8> = vec![];
        for _ in 0..r.below(8) {
            let mut nm = pool[r.below(pool.len() as u64) as usize].to_vec(); if r.below(3) == 0 { for c in nm.iter_mut() { if *c == b'-' { *c = b'_' } else if *c == b'_' { *c = b'-' } } }
            line.extend_from_slice(&nm);
            match r.below(6) { 0 | 1 => { line.push(b'='); line.extend_from_slice(match r.below(6) { 0 => &b""[..], 1 => b"1", 2 => b"\"a b\"", 3 => b"x=y", 4 => b"on", _ => b"--" }) } _ => {} }
            line.push(b' ');
            if r.below(12) == 0 { line.extend_from_slice(if r.below(2) == 0 { b"-- " } else { b"--" }) }
        }
        if r.below(40) == 0 { while line.len() < 2100 + r.below(100) as usize { line.extend_from_slice(b"foo=1 "); } }
        line.retain(|c| *c != 0);
        let mut outs: Vec<Vec<Ev>> = vec![];
        for which in 0..2 {
            unsafe {
                let tab = e_table() as *mut u8;
                let mut names_at: Vec<usize> = vec![];
                for (i, (ni, early, _)) in ents.iter().enumerate() {
                    let e = tab.add(i * 24);
                    let p: usize = if *ni == usize::MAX { 0 } else { arena[*ni].as_ptr() as usize }; names_at.push(p);
                    std::ptr::copy_nonoverlapping(p.to_le_bytes().as_ptr(), e, 8);
                    let f = e_sf(i as i32) as usize; std::ptr::copy_nonoverlapping(f.to_le_bytes().as_ptr(), e.add(8), 8);
                    std::ptr::copy_nonoverlapping((*early as i32).to_le_bytes().as_ptr(), e.add(16), 4);
                }
                RET.with(|x| *x.borrow_mut() = ents.iter().map(|e| e.2).collect());
                let cl = e_cmdline(); std::ptr::write_bytes(cl, 0, 2048);
                let m = line.len().min(2047); std::ptr::copy_nonoverlapping(line.as_ptr(), cl, m);
                LOG.with(|l| l.borrow_mut().clear());
                if which == 0 { e_reset(); e_c_early(); e_c_early(); } else { h::test_reset_done(); h::parse_early_param(); h::parse_early_param(); }
            }
            outs.push(LOG.with(|l| l.borrow().clone()));
        }
        if outs[0] != outs[1] { eprintln!("MISMATCH line={:?}\n  C   : {:?}\n  Rust: {:?}", String::from_utf8_lossy(&line), outs[0], outs[1]); std::process::exit(1); }
        tot += 1; if line.len() > 2047 { trunc += 1 }
        for e in &outs[0] { match e { Ev::Set(..) => sets += 1, Ev::Msg(_) => mal += 1 } }
    }
    println!("early_cmp: {tot} boot command lines equal C == Rust (setup_func calls in order with values, 'Malformed early option' lines, second call a no-op); setup_func calls {sets}, malformed lines {mal}, lines longer than 2047 bytes {trunc}");
}
