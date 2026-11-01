// Userspace differential: params_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C cut out of the pristine params.c / cmdline.c
// (params_ref.c). Random parameter tables, command lines (quotes, `--`, dashes/underscores, unknown names, overlong tokens, byte noise), levels,
// callback results (0, -ENOENT, -ENOSPC, -EINVAL, others), callbacks that enable "interrupts", unlock/lock pairs, lockdown and taint paths.
// Compared per case: the return value (NULL / ERR_PTR(code) / offset into the buffer), the whole buffer (next_arg writes NULs into it), and the
// ordered event log: every set() and unknown() call with its arguments, every kernel_param_lock/unlock, security_locked_down, add_taint, every printk (level + text).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs)]
#[path = "PARAMSRS"]
mod h;
use h::{KernelParam, KernelParamOps};
use std::cell::RefCell;
use std::ffi::{c_char, c_void};
extern "C" {
    fn set_lockdown(v: i32);
    fn set_irq(v: bool);
    fn ref_parameq(a: *const c_char, b: *const c_char) -> bool;
    fn ref_parameqn(a: *const c_char, b: *const c_char, n: usize) -> bool;
    fn ref_parse_args(doing: *const c_char, args: *mut c_char, params: *const KernelParam, num: u32, min: i16, max: i16, arg: *mut c_void, unknown: Option<h::UnknownFn>) -> *mut c_char;
}
#[derive(PartialEq, Debug, Clone)]
enum Ev { Lockdown(i64), Taint(i64, i64), Lock(i64), Unlock(i64), Msg(Vec<u8>), Set(usize, Option<Vec<u8>>), Unknown(Vec<u8>, Option<Vec<u8>>, Vec<u8>, i64) }
thread_local! { static LOG: RefCell<Vec<Ev>> = RefCell::new(Vec::new()); static RET: RefCell<Vec<(i32, bool)>> = RefCell::new(Vec::new()); static UNK: RefCell<i32> = RefCell::new(0); }
#[no_mangle] pub extern "C" fn log_event(kind: i32, a: i64, b: i64) { LOG.with(|l| l.borrow_mut().push(match kind { 1 => Ev::Lockdown(a), 2 => Ev::Taint(a, b), 3 => Ev::Lock(a), _ => Ev::Unlock(a) })); }
#[no_mangle] pub extern "C" fn log_msg(t: *const u8, n: i32) { LOG.with(|l| l.borrow_mut().push(Ev::Msg(unsafe { std::slice::from_raw_parts(t, n as usize).to_vec() }))); }
unsafe fn cs(p: *const c_char) -> Vec<u8> { std::ffi::CStr::from_ptr(p).to_bytes().to_vec() }
unsafe extern "C" fn cb_set(val: *const c_char, kp: *const KernelParam) -> i32 {
    let idx = (*kp).arg as usize;
    LOG.with(|l| l.borrow_mut().push(Ev::Set(idx, if val.is_null() { None } else { Some(cs(val)) })));
    let (ret, flip) = RET.with(|r| r.borrow()[idx]);
    if flip { set_irq(false); }
    ret
}
unsafe extern "C" fn cb_unknown(p: *mut c_char, v: *mut c_char, d: *const c_char, a: *mut c_void) -> i32 {
    LOG.with(|l| l.borrow_mut().push(Ev::Unknown(cs(p), if v.is_null() { None } else { Some(cs(v)) }, cs(d), a as i64)));
    UNK.with(|u| *u.borrow())
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T { &v[self.below(v.len() as u64) as usize] }
}
const CODES: [i32; 9] = [0, 0, 0, -2, -28, -22, -1, -5, 7];
fn gen_line(r: &mut Rng, names: &[Vec<u8>]) -> Vec<u8> {
    let mut s: Vec<u8> = vec![];
    let sp = |r: &mut Rng, s: &mut Vec<u8>| { for _ in 0..1 + r.below(3) { s.push(*r.pick(&[b' ', b' ', b' ', b'\t', b'\n'])); } };
    if r.below(3) == 0 { sp(r, &mut s); }
    for _ in 0..r.below(7) {
        match r.below(14) {
            0 => s.extend_from_slice(b"--"),
            1 => { s.extend_from_slice(b"-- "); s.extend_from_slice(b"init=/bin/sh x=y") }
            2 => s.extend_from_slice(b"--=v"),
            3 => s.extend_from_slice(*r.pick(&[&b"-"[..], b"---", b"=", b"=x", b"\"\"", b"\"", b"\" \"", b"a\"b c\"d"])),
            4 => { for _ in 0..r.below(60) { s.push(match r.below(8) { 0 => b'"', 1 => b'=', 2 => b' ', 3 => b'-', 4 => b'_', _ => 1 + r.below(254) as u8 }); } }
            5 => { for _ in 0..(300 + r.below(3000)) { s.push(b'a' + r.below(3) as u8); } if r.below(2) == 0 { s.extend_from_slice(b"=v") } }
            _ => {
                let mut n = r.pick(names).clone();
                if r.below(3) == 0 { for c in n.iter_mut() { if *c == b'-' { *c = b'_' } else if *c == b'_' { *c = b'-' } } }
                if r.below(8) == 0 { s.push(b'"'); s.extend_from_slice(&n); s.push(b'"'); } else { s.extend_from_slice(&n); }
                match r.below(6) {
                    0 | 1 => { s.push(b'='); let v: &[u8] = *r.pick(&[&b""[..], b"1", b"on", b"\"a b\"", b"\"quoted\"", b"x=y", b"\"unterminated", b"a\"b c\"d", b"\"\"", b"-", b"--"]); s.extend_from_slice(v); }
                    2 => { s.extend_from_slice(b"=\""); for _ in 0..r.below(20) { s.push(b'a' + r.below(26) as u8); } if r.below(2) == 0 { s.push(b'"') } }
                    _ => {}
                }
            }
        }
        sp(r, &mut s);
    }
    if r.below(2) == 0 { while s.last().map_or(false, |c| *c == b' ' || *c == b'\t' || *c == b'\n') { s.pop(); } }
    s.retain(|c| *c != 0);
    s
}
#[derive(PartialEq, Debug)]
struct Out { ret: String, buf: Vec<u8>, log: Vec<Ev>, irq: bool }
fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let mut r = Rng(0x9e3779b97f4a7c15);
    let long: Vec<u8> = std::iter::repeat(b'q').take(300).collect();
    let names: Vec<Vec<u8>> = [&b"foo"[..], b"bar-baz", b"bar_baz", b"noarg", b"a-b-c", b"a_b-c", b"console", b"x", b"xyz", b"Foo", b"early-param", b"--", b"-", b"a=b"].iter().map(|v| v.to_vec()).chain([long.clone()]).collect();
    let (mut tot, mut dash, mut unk, mut errp, mut lockn, mut warnn, mut taint, mut lockd, mut msgs, mut sets) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    // exhaustive parameq / parameqn on a small alphabet
    {
        let alpha = [b'a', b'-', b'_', b'b', 0u8]; let mut cases = 0u64;
        let mut strs: Vec<Vec<u8>> = vec![];
        fn gen(prefix: &mut Vec<u8>, left: usize, alpha: &[u8], out: &mut Vec<Vec<u8>>) { let mut s = prefix.clone(); s.push(0); out.push(s); if left == 0 { return; } for &c in alpha.iter().filter(|&&c| c != 0) { prefix.push(c); gen(prefix, left - 1, alpha, out); prefix.pop(); } }
        gen(&mut vec![], 5, &alpha, &mut strs);
        for a in &strs { for b in &strs { unsafe {
            let (pa, pb) = (a.as_ptr() as *const c_char, b.as_ptr() as *const c_char);
            assert_eq!(h::parameq(pa, pb), ref_parameq(pa, pb), "parameq {:?} {:?}", a, b); cases += 1;
            // parameqn: n bounded so that neither string is read past its terminator in the C either (n <= first differing index + 1 is safe; use min(len)+1)
            let m = a.len().min(b.len());
            for nn in 0..=m { assert_eq!(h::parameqn(pa, pb, nn), ref_parameqn(pa, pb, nn), "parameqn {:?} {:?} {}", a, b, nn); cases += 1; }
        } } }
        println!("parameq/parameqn exhaustive: {} strings ({} pairs), {} calls equal C == Rust", strs.len(), strs.len() * strs.len(), cases);
    }
    for case in 0..n {
        let nparams = r.below(9) as usize;
        let ops = [KernelParamOps { flags: 0, set: cb_set, get: std::ptr::null(), free: std::ptr::null() }, KernelParamOps { flags: 1, set: cb_set, get: std::ptr::null(), free: std::ptr::null() }];
        let mut tab: Vec<KernelParam> = vec![]; let mut rets: Vec<(i32, bool)> = vec![];
        let mut pnames: Vec<Vec<u8>> = vec![];
        for i in 0..nparams {
            let mut nm = r.pick(&names).clone(); nm.push(0); pnames.push(nm); rets.push((*r.pick(&CODES), r.below(6) == 0));
            let _ = i;
        }
        for i in 0..nparams {
            tab.push(KernelParam { name: pnames[i].as_ptr() as *const c_char, module: if r.below(2) == 0 { std::ptr::null_mut() } else { (0x1000 + i * 8) as *mut c_void },
                ops: &ops[r.below(2) as usize], perm: 0, level: *r.pick(&[0i8, 0, -1, 1, 2, -2, 127, -128, 3]), flags: r.below(4) as u8, arg: i as *mut c_void });
        }
        RET.with(|x| *x.borrow_mut() = rets.clone());
        let (min, max): (i16, i16) = if r.below(2) == 0 { (-32768, 32767) } else { (*r.pick(&[-2i16, 0, 1, -1, 3, -128]), *r.pick(&[0i16, 1, 2, -1, 127, 5])) };
        let doing = *r.pick(&[&b"Booting kernel\0"[..], b"early options\0", b"mymod\0", b"\0"]);
        let line = gen_line(&mut r, &names);
        let lockdown = *r.pick(&[0, 0, 1]); let irq0 = r.below(2) == 0; let unkcode = *r.pick(&[0, 0, -2, -28, -22, 5, -1]); let use_unk = r.below(3) != 0;
        let argp = (0x77 + r.below(9)) as *mut c_void;
        let mut buf0 = line.clone(); buf0.push(0); for _ in 0..16 { buf0.push(0xA5); }
        let mut outs: Vec<Out> = vec![];
        for which in 0..2 {
            let mut buf = buf0.clone();
            LOG.with(|l| l.borrow_mut().clear()); UNK.with(|u| *u.borrow_mut() = unkcode);
            let rp = unsafe {
                set_lockdown(lockdown); set_irq(irq0);
                let f: Option<h::UnknownFn> = if use_unk { Some(cb_unknown) } else { None };
                if which == 0 { ref_parse_args(doing.as_ptr() as *const c_char, buf.as_mut_ptr() as *mut c_char, tab.as_ptr(), nparams as u32, min, max, argp, f) }
                else { h::parse_args(doing.as_ptr() as *const c_char, buf.as_mut_ptr() as *mut c_char, tab.as_ptr(), nparams as u32, min, max, argp, f) }
            };
            let base = buf.as_ptr() as usize; let rv = rp as usize;
            let ret = if rv == 0 { "NULL".to_string() } else if rv >= base && rv <= base + buf.len() { format!("buf+{}", rv - base) } else if (rv as isize) < 0 && (rv as isize) > -4096 { format!("ERR({})", rv as isize) } else { format!("RAW({rv:#x})") };
            let irq = unsafe { extern "C" { fn test_irqs_disabled() -> bool; } test_irqs_disabled() };
            outs.push(Out { ret, buf, log: LOG.with(|l| l.borrow().clone()), irq });
        }
        if outs[0] != outs[1] {
            eprintln!("MISMATCH case {case}: line={:?} min={min} max={max} unk={use_unk}/{unkcode} lockdown={lockdown} irq0={irq0}\n  C   : ret={} irq={}\n  Rust: ret={} irq={}",
                String::from_utf8_lossy(&line), outs[0].ret, outs[0].irq, outs[1].ret, outs[1].irq);
            let (a, b) = (&outs[0].log, &outs[1].log);
            for k in 0..a.len().max(b.len()) { if a.get(k) != b.get(k) { eprintln!("  log[{k}]: C {:?}\n          Rust {:?}", a.get(k), b.get(k)); break; } }
            if outs[0].buf != outs[1].buf { eprintln!("  buffers differ"); }
            std::process::exit(1);
        }
        let o = &outs[0]; tot += 1;
        if o.ret.starts_with("ERR") { errp += 1 }
        for e in &o.log { match e { Ev::Lock(_) => lockn += 1, Ev::Unknown(..) => unk += 1, Ev::Taint(..) => taint += 1, Ev::Lockdown(_) => lockd += 1, Ev::Set(..) => sets += 1,
            Ev::Msg(m) => { msgs += 1; if m.windows(8).any(|w| w == b"enabled ") { warnn += 1 } } _ => {} } }
        if line.windows(2).any(|w| w == b"--") { dash += 1 }
    }
    println!("params_cmp: {tot} command lines equal C == Rust (return value, buffer, event log); set() calls {sets}, unknown() calls {unk}, lock/unlock pairs {lockn}, lockdown checks {lockd}, taints {taint}, printk lines {msgs} (irq-enabled warnings {warnn}), ERR_PTR returns {errp}, lines containing \"--\" {dash}");
}
