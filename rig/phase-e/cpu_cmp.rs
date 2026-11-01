// Userspace differential: common_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C cut out of the pristine common.c (cpu_ref.c).
// A random CPU (CPUID answers), random starting state (the cpuinfo_x86 bytes, boot_cpu_data, cpu_caps_set / cpu_caps_cleared, this_cpu, cpu_devs,
// the registration array, the command-line options, __pgtable_l5_enabled, alternatives_patched), then the same operation on both sides from the
// same state; compared: every byte of the struct, boot_cpu_data, both forced-caps arrays, this_cpu, cpu_devs, the pr_err_once flag, the string
// handed to the parser, and the ordered log of every CPUID instruction, printk, taint, warning and stub call (with the hash of the struct each stub saw).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs, static_mut_refs)]
#[path = "CPURS"]
mod h;
use std::ffi::c_char;
extern "C" {
    fn c_sizeof() -> usize;
    fn c_reg_n() -> usize;
    fn c_boot() -> *mut u8;
    fn c_caps_set() -> *mut u32;
    fn c_caps_cleared() -> *mut u32;
    fn c_l5() -> *mut u32;
    fn c_altp() -> *mut i32;
    fn c_devs_ptr() -> *const *const u8;
    fn c_log_reset();
    fn c_log() -> *const c_char;
    fn c_loglen() -> usize;
    fn c_set_opts(names: *const u8, present: *const i32, values: *const u8, n: i32);
    fn c_set_cpu(seed: u64, max_basic: u32, max_ext: u32, vendor: *const u32, sig: u32, ebx1: u32, clflush: u32, leaf7_eax: u32, l8: u32, density: i32);
    fn c_set_reg(which: *const i32);
    fn c_reset_state(this_idx: i32, devs: *const i32);
    fn c_this_idx() -> i32;
    fn c_dev_idx(d: *const u8) -> i32;
    fn c_once_flags(n: *mut usize) -> *const u8;
    fn c_cpu_detect(c: *mut u8);
    fn c_get_cpu_vendor(c: *mut u8);
    fn c_get_cpu_cap(c: *mut u8);
    fn c_get_cpu_address_sizes(c: *mut u8);
    fn c_filter(c: *mut u8, warn: i32);
    fn c_apply_forced_caps(c: *mut u8);
    fn c_init_cpu_devs();
    fn c_early_cpu_init();
    fn c_early_identify_cpu(c: *mut u8);
    fn c_parse_set_clear(arg: *mut c_char, set: i32) -> i32;
    fn c_cpu_parse_early_param();
    fn c_set_arch(v: u64);
    fn c_bugbits(c: *mut u8);
    fn c_table_entries(which: i32, out: *mut u32, max: i32) -> i32;
}
struct Rng(u64);
macro_rules! pick { ($r:expr, $a:expr) => {{ let a = &$a; let i = $r.below(a.len() as u64) as usize; a[i] }}; }
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}
const NDEVS: usize = 6;
const BUG_FEATURES: [u32; 17] = [4 * 32 + 31, 13 * 32 + 26, 20 * 32 + 8, 7 * 32 + 30, 9 * 32 + 11, 4 * 32 + 30, 9 * 32 + 18, 13 * 32 + 29, 20 * 32 + 29, 4 * 32 + 28, 21 * 32 + 4, 13 * 32 + 12, 13 * 32 + 30, 21 * 32 + 1, 21 * 32 + 2, 7 * 32 + 28, 18 * 32 + 29];
fn encode_sig(fam: u32, model: u32, step: u32) -> u32 {
    let (base, extf) = if fam >= 0xf { (0xf, fam - 0xf) } else { (fam, 0) };
    let (m, em) = if fam >= 6 { (model & 0xf, model >> 4) } else { (model & 0xf, 0) };
    (extf << 20) | (em << 16) | (base << 8) | (m << 4) | (step & 0xf)
}
fn s12(s: &[u8]) -> [u32; 3] {
    let mut b = [0u8; 12];
    for (i, x) in s.iter().take(12).enumerate() { b[i] = *x; }
    [u32::from_le_bytes(b[0..4].try_into().unwrap()), u32::from_le_bytes(b[4..8].try_into().unwrap()), u32::from_le_bytes(b[8..12].try_into().unwrap())]
}
// the vendor-id string registers as CPUID returns them: leaf 0 EBX, EDX, ECX = bytes 0-3, 4-7, 8-11
fn vendor_words(r: &mut Rng) -> [u32; 3] {
    let names: [&[u8]; 9] = [b"GenuineIntel", b"AuthenticAMD", b"HygonGenuine", b"CentaurHauls", b"  Shanghai  ", b"TwoIdentsInc", b"OrAnotherOne", b"AuthenticAMD", b"            "];
    let w = match r.below(10) {
        0..=6 => s12(pick!(r, &names[..])),
        7 => { let mut b = [0u8; 12]; for x in b.iter_mut() { *x = 0x20 + r.below(95) as u8; } s12(&b) }
        8 => { let mut v = s12(pick!(r, &names[..])); v[(r.below(3)) as usize] ^= 1 << r.below(32); v }
        _ => [r.next() as u32, r.next() as u32, r.next() as u32],
    };
    // cpuid(0) returns EBX = bytes 0-3, EDX = 4-7, ECX = 8-11; the C reads (ebx, edx, ecx) into x86_vendor_id[0], [4], [8]: a vendor string is bytes 0-3 | 4-7 | 8-11
    [w[0], w[1], w[2]]
}
fn rnd_sig(r: &mut Rng) -> u32 {
    let fam = pick!(r, [0u32, 3, 4, 5, 6, 6, 6, 0xf, 0xf, 0xf, 7, 0xe, r.next() as u32 & 0xf]);
    let ext_fam = if r.below(2) == 0 { r.below(0x100) as u32 } else { pick!(r, [0, 1, 0x8, 0xa, 0xff]) };
    let ext_model = r.below(0x10) as u32;
    let model = r.below(0x10) as u32;
    let step = r.below(0x10) as u32;
    let sig = (ext_fam << 20) | (ext_model << 16) | (fam << 8) | (model << 4) | step;
    if r.below(8) == 0 { sig ^ ((r.next() as u32) & 0xf000f000) } else { sig }
}
struct Case {
    seed: u64, max_basic: u32, max_ext: u32, vendor: [u32; 3], sig: u32, ebx1: u32, clflush: u32, leaf7_eax: u32, l8: u32, density: i32,
    c: Vec<u8>, boot: Vec<u8>, caps_set: [u32; 24], caps_cleared: [u32; 24], this_idx: i32, devs: [i32; 16], reg: Vec<i32>, l5: u32, altp: i32,
    names: Vec<u8>, present: Vec<i32>, values: Vec<u8>, nopts: i32, arch: u64,
}
const OPTS: [&str; 7] = ["noxsave", "noxsaveopt", "noxsaves", "nousershstk", "fred", "clearcpuid", "setcpuid"];
fn rnd_list(r: &mut Rng) -> String {
    if r.below(5) == 0 {   // every entry invalid: the parser reports it and changes nothing (taint stays 0)
        let bad = ["bogus", "99999", "4294967296", "-1", "FPU", "fpu ", "x", "704", "0x10", "", "nonsense_flag"];
        let n = 1 + r.below(3);
        return (0..n).map(|_| pick!(r, &bad[..]).to_string()).collect::<Vec<_>>().join(",");
    }
    let words = ["fpu", "avx", "xsave", "mwait", "nopl", "la57", "fred", "spec_ctrl", "cpu_meltdown", "spectre_v1", "l1tf", "bogus", "", "x2apic", "hypervisor", "ibrs", "0", "5", "32", "703", "704", "99999", "4294967295", "4294967296", "+7", "7\n", "-1", "0x10", " 3", "3 ", "swapgs", "mds", "sse4_2", "FPU", "fpu ", "retbleed", "bhi", "its"];
    let n = r.below(5) + (r.below(4) == 0) as u64 * r.below(12);
    let mut v = Vec::new();
    for _ in 0..n { v.push(pick!(r, &words[..]).to_string()); }
    let sep = if r.below(6) == 0 { ",," } else { "," };
    let mut s = v.join(sep);
    if r.below(8) == 0 { s.push(','); }
    if r.below(30) == 0 { s = s.repeat(3); }
    s.chars().take(127).collect()
}
fn gen(r: &mut Rng, sz: usize, reg_n: usize, ents: &[[u32; 6]]) -> Case {
    let max_basic = pick!(r, [0u32, 1, 2, 5, 6, 7, 8, 9, 0xd, 0xe, 0x10, 0x16, 0x1f, 0x80000000, 0x80000001, 0xffffffff, 0xfffffffe, r.next() as u32, r.below(0x20) as u32]);
    let max_ext = pick!(r, [0u32, 0x7fffffff, 0x80000000, 0x80000001, 0x80000006, 0x80000007, 0x80000008, 0x80000009, 0x8000000a, 0x8000001e, 0x8000001f, 0x80000020, 0x80000021, 0x80000026, 0x8000ffff, 0x80010000, 0x90000000, 0xffff0000, r.next() as u32, 0x80000000 | r.below(0x30) as u32]);
    let leaf7_eax = pick!(r, [0u32, 0, 1, 1, 2, 0xffffffff, r.next() as u32]);
    let l8 = pick!(r, [0x3024u32, 0x3030, 0x2434, 0x2028, 0, 0xff, 0xff00, r.next() as u32, 0x3039]);
    let mut c = vec![0u8; sz];
    let fill = r.below(3);
    for x in c.iter_mut() { *x = match fill { 0 => 0, 1 => r.next() as u8, _ => if r.below(4) == 0 { r.next() as u8 } else { 0 } }; }
    if r.below(6) != 0 { for i in 0x9c..0xa0 { c[i] = 0; } }   // x86_vendor_id[12..16]: NUL in a real kernel (bss / copied from a CPU that identified itself), so that the vendor strings can match
    let vend = vendor_words(r);
    if r.below(4) != 0 { for k in 0..3 { c[0x90 + 4 * k..0x94 + 4 * k].copy_from_slice(&vend[k].to_le_bytes()); } }   // as cpu_detect() leaves it
    let mut boot = vec![0u8; sz];
    for x in boot.iter_mut() { *x = if r.below(2) == 0 { 0 } else { r.next() as u8 }; }
    let sparse = |r: &mut Rng| { let mut a = [0u32; 24]; if r.below(3) != 0 { for _ in 0..r.below(6) { let w = r.below(24) as usize; a[w] |= 1 << r.below(32); } } a };
    let (caps_set, mut caps_cleared) = (sparse(r), sparse(r));
    if r.below(3) == 0 { for i in 0..24 { caps_cleared[i] |= caps_set[i] & r.next() as u32; } }
    let this_idx = if r.below(3) == 0 { -1 } else { r.below(NDEVS as u64) as i32 };
    let nreg = r.below(13) as usize;
    let mut devs = [-1i32; 16];
    for i in 0..nreg.min(12) { devs[i] = if r.below(10) == 0 { -1 } else { r.below(NDEVS as u64) as i32 }; }
    if r.below(2) == 0 { for i in 0..12 { devs[i] = (i % NDEVS) as i32; } }
    let reg: Vec<i32> = (0..reg_n).map(|_| if r.below(8) == 0 { NDEVS as i32 } else { r.below(NDEVS as u64) as i32 }).collect();
    let mut names = vec![0u8; 32 * 7]; let mut present = vec![0i32; 7]; let mut values = vec![0u8; 200 * 7];
    for (i, o) in OPTS.iter().enumerate() {
        names[32 * i..32 * i + o.len()].copy_from_slice(o.as_bytes());
        present[i] = (r.below(3) == 0) as i32;
        let val: String = match i { 4 => (pick!(r, ["on", "off", "o", "onn", "", "ON", "on,x", "no"])).to_string(), 5 | 6 => if r.below(3) == 0 { String::new() } else { rnd_list(r) }, _ => String::new() };
        values[200 * i..200 * i + val.len()].copy_from_slice(val.as_bytes());
        if (i == 4 || i == 5 || i == 6) && r.below(4) != 0 { present[i] = 1; }
    }
    // a CPU that is in one of the real tables (60%): the vendor string, the signature and the boot_cpu_data fields agree on it
    let mut vendor = if r.below(2) == 0 { vend } else { vendor_words(r) };
    let mut sig = rnd_sig(r);
    let mut micro = pick!(r, [0u32, 0x1, 0x20, 0x500, 0xa000000, 0x80000001, r.next() as u32]);
    if r.below(10) < 6 && !ents.is_empty() {
        let e = ents[r.below(ents.len() as u64) as usize];
        let vnum = if e[0] == 0xffff { pick!(r, [0u32, 2, 2, 9]) } else { e[0] };
        let vstr: &[u8] = match vnum { 0 => b"GenuineIntel", 2 => b"AuthenticAMD", 9 => b"HygonGenuine", 5 => b"CentaurHauls", 10 => b"  Shanghai  ", _ => b"GenuineIntel" };
        let step = if e[3] != 0 { let mut st = r.below(16) as u32; for _ in 0..8 { if e[3] & (1 << st) != 0 { break; } st = r.below(16) as u32; } st } else { r.below(16) as u32 };
        let fam = if e[1] == 0 { pick!(r, [6u32, 0x15, 0x17, 0x19, 6]) } else { e[1] };
        let model = if e[2] == 0 { r.below(0x100) as u32 } else { e[2] };
        vendor = s12(vstr); sig = encode_sig(fam, model, step);
        c[0] = model as u8; c[1] = fam as u8; c[2] = vnum as u8; c[4] = step as u8;
        for (i, b) in boot.iter_mut().enumerate() { if i == 0 { *b = model as u8 } else if i == 1 { *b = fam as u8 } else if i == 2 { *b = vnum as u8 } else if i == 4 { *b = step as u8 } }
        if e[5] != 0 && r.below(2) == 0 { micro = pick!(r, [e[5].wrapping_sub(1), e[5], e[5].wrapping_add(1), e[5] | 0x80000000]); }
    }
    // the feature bits cpu_set_bug_bits() tests: each set with probability 1/3, in both the scratch struct and boot_cpu_data
    for f in BUG_FEATURES.iter() { let (w, b) = ((*f / 32) as usize, *f % 32); for buf in [&mut c, &mut boot] { let off = 0x30 + 4 * w; let mut v = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()); if r.below(3) == 0 { v |= 1 << b } else if r.below(3) == 0 { v &= !(1 << b) }; buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); } }
    for buf in [&mut c, &mut boot] { buf[0x148..0x14c].copy_from_slice(&micro.to_le_bytes()); }
    let arch = if r.below(3) == 0 { 0 } else { let mut a = r.next() & 0x1f_ffff_ffff; if r.below(4) == 0 { a |= 1 << 62 }; a };
    Case { seed: r.next(), max_basic, max_ext, vendor, sig, ebx1: (r.next() as u32 & 0xffff_ff00) | (r.below(0x41) as u32) << 8, clflush: r.below(2) as u32, leaf7_eax, l8,
           density: r.below(5) as i32, c, boot, caps_set, caps_cleared, this_idx, devs, reg, l5: pick!(r, [0, 0, 1, 2]), altp: pick!(r, [0, 0, 1, 5]), names, present, values, nopts: 7, arch }
}
#[derive(PartialEq, Debug, Clone)]
struct Snap { c: Vec<u8>, boot: Vec<u8>, set: Vec<u32>, cleared: Vec<u32>, this_idx: i32, devs: Vec<i32>, once: bool, arg: Vec<u8>, ret: i64, log: Vec<u8> }
unsafe fn load(cs: &Case, arg: Option<&[u8]>, boot_is_c: bool) -> (Vec<u8>, Vec<u8>) {
    c_set_cpu(cs.seed, cs.max_basic, cs.max_ext, cs.vendor.as_ptr(), cs.sig, cs.ebx1, cs.clflush, cs.leaf7_eax, cs.l8, cs.density);
    std::ptr::copy_nonoverlapping(cs.boot.as_ptr(), c_boot(), cs.boot.len());
    if boot_is_c { std::ptr::copy_nonoverlapping(cs.c.as_ptr(), c_boot(), cs.c.len()); }
    std::ptr::copy_nonoverlapping(cs.caps_set.as_ptr(), c_caps_set(), 24);
    std::ptr::copy_nonoverlapping(cs.caps_cleared.as_ptr(), c_caps_cleared(), 24);
    *c_l5() = cs.l5; *c_altp() = cs.altp;
    c_set_arch(cs.arch);
    c_reset_state(cs.this_idx, cs.devs.as_ptr());
    let reg: Vec<i32> = cs.reg.clone(); c_set_reg(reg.as_ptr());
    c_set_opts(cs.names.as_ptr(), cs.present.as_ptr(), cs.values.as_ptr(), cs.nopts);
    h::test_once(Some(false));
    c_log_reset();
    let mut a = vec![0u8; 256];
    if let Some(s) = arg { a[..s.len()].copy_from_slice(s); }
    (cs.c.clone(), a)
}
unsafe fn snap(c: &[u8], c_is_boot: bool, arg: &[u8], ret: i64) -> Snap {
    let sz = c_sizeof();
    let boot = std::slice::from_raw_parts(c_boot(), sz).to_vec();
    let mut n = 0usize; let f = c_once_flags(&mut n); let cflag = std::slice::from_raw_parts(f, n).iter().any(|b| *b != 0);
    let rflag = h::test_once(None);
    Snap { c: if c_is_boot { boot.clone() } else { c.to_vec() }, boot, set: std::slice::from_raw_parts(c_caps_set(), 24).to_vec(), cleared: std::slice::from_raw_parts(c_caps_cleared(), 24).to_vec(),
           this_idx: c_this_idx(), devs: (0..16).map(|i| c_dev_idx(*c_devs_ptr().add(i))).collect(), once: cflag | rflag, arg: arg.to_vec(), ret,
           log: std::slice::from_raw_parts(c_log() as *const u8, c_loglen()).to_vec() }
}
fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|v| v.parse().ok()).unwrap_or(100000);
    let mut r = Rng(0x2026_1005_u64 ^ std::env::var("SEED").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(1));
    let (sz, reg_n) = unsafe { (c_sizeof(), c_reg_n()) };
    let mut ents: Vec<[u32; 6]> = Vec::new();
    for which in 0..3 { let mut buf = vec![0u32; 6 * 512]; let n = unsafe { c_table_entries(which, buf.as_mut_ptr(), 512) } as usize; for i in 0..n { ents.push(buf[6 * i..6 * i + 6].try_into().unwrap()); } }
    let ops = ["detect", "vendor", "cap", "addrsz", "filter", "forced", "initdevs", "earlyinit", "earlyident", "setclear", "earlyparam", "bugbits", "bugbits"];
    let mut counts = std::collections::BTreeMap::new();
    let mut bugruns = 0u64;
    let (mut cpuids, mut printks, mut taints, mut onces, mut vend_known, mut vend_unknown, mut warns) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for case in 0..n {
        let op = ops[(case as usize) % ops.len()];
        let cs = gen(&mut r, sz, reg_n, &ents);
        let list = rnd_list(&mut r);
        let set = (r.below(2)) as i32; let warn = (r.below(2)) as i32;
        let boot_is_c = matches!(op, "earlyident" | "bugbits");
        let argb: Vec<u8> = list.bytes().collect();
        let mut res: Vec<Snap> = Vec::new();
        for side in 0..2 {
            unsafe {
                let (mut cc, mut arg) = load(&cs, if op == "setclear" { Some(&argb) } else { None }, boot_is_c);
                let cp: *mut u8 = if boot_is_c { c_boot() } else { cc.as_mut_ptr() };
                let ap = arg.as_mut_ptr() as *mut c_char;
                let mut ret = 0i64;
                if side == 0 {
                    match op {
                        "detect" => c_cpu_detect(cp), "vendor" => c_get_cpu_vendor(cp), "cap" => c_get_cpu_cap(cp), "addrsz" => c_get_cpu_address_sizes(cp), "filter" => c_filter(cp, warn),
                        "forced" => c_apply_forced_caps(cp), "initdevs" => c_init_cpu_devs(), "earlyinit" => c_early_cpu_init(), "earlyident" => c_early_identify_cpu(cp),
                        "setclear" => ret = c_parse_set_clear(ap, set) as i64, "earlyparam" => c_cpu_parse_early_param(), "bugbits" => c_bugbits(cp), _ => unreachable!(),
                    }
                } else {
                    match op {
                        "detect" => h::cpu_detect_impl(cp), "vendor" => h::get_cpu_vendor_impl(cp), "cap" => h::get_cpu_cap_impl(cp), "addrsz" => h::get_cpu_address_sizes_impl(cp),
                        "filter" => h::filter_cpuid_features_impl(cp, warn != 0), "forced" => h::apply_forced_caps_impl(cp), "initdevs" => h::init_cpu_devs_impl(), "earlyinit" => h::early_cpu_init_impl(),
                        "earlyident" => h::early_identify_cpu_impl(cp), "bugbits" => h::cpu_set_bug_bits_impl(cp), "setclear" => ret = h::parse_set_clear_cpuid(ap, set != 0) as i64, "earlyparam" => h::cpu_parse_early_param(), _ => unreachable!(),
                    }
                }
                res.push(snap(&cc, boot_is_c, &arg, ret));
            }
        }
        if res[0] != res[1] {
            println!("MISMATCH case {case} op {op} sig {:#x} vendor {:x?} max_basic {:#x} max_ext {:#x} set {set} warn {warn} list '{list}'", cs.sig, cs.vendor, cs.max_basic, cs.max_ext);
            let (a, b) = (&res[0], &res[1]);
            if a.c != b.c { for i in 0..a.c.len() { if a.c[i] != b.c[i] { println!("  c[{i:#x}]: C {:#x} Rust {:#x}", a.c[i], b.c[i]); break; } } }
            if a.boot != b.boot { for i in 0..a.boot.len() { if a.boot[i] != b.boot[i] { println!("  boot[{i:#x}]: C {:#x} Rust {:#x}", a.boot[i], b.boot[i]); break; } } }
            println!("  set {} cleared {} this {} / {} devs {} once {} / {} arg {} ret {} / {}", a.set == b.set, a.cleared == b.cleared, a.this_idx, b.this_idx, a.devs == b.devs, a.once, b.once, a.arg == b.arg, a.ret, b.ret);
            println!("  C log:\n{}\n  Rust log:\n{}", String::from_utf8_lossy(&a.log), String::from_utf8_lossy(&b.log));
            std::process::exit(1);
        }
        *counts.entry(op).or_insert(0u64) += 1;
        let log = String::from_utf8_lossy(&res[0].log);
        cpuids += log.matches("cpuid ").count() as u64; printks += log.matches("printk[").count() as u64; taints += log.matches("add_taint").count() as u64; warns += log.matches("WARN").count() as u64;
        onces += res[0].once as u64;
        if op == "bugbits" && res[0].boot[0x30 + 4 * 22..0x30 + 4 * 24].iter().any(|b| *b != 0) { bugruns += 1; }
        if op == "vendor" || op == "earlyident" || op == "earlyinit" { if res[0].this_idx >= 0 { vend_known += 1 } else { vend_unknown += 1 } }
    }
    println!("cpu_cmp: {n} cases (reg_n {reg_n}), the C and the Rust agree on every one (struct bytes, boot_cpu_data, cpu_caps_set/cleared, this_cpu, cpu_devs, once flag, parser buffer + return, and the whole CPUID/printk/taint/stub log)");
    println!("  per op: {}", counts.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", "));
    println!("  table entries available {} (whitelist, blacklist, latest microcode), bug words set in {} of the bug-bit runs", ents.len(), bugruns);
    println!("  CPUID instructions {cpuids}, printk records {printks}, taints {taints}, WARNs {warns}, vendor-unknown-once flag set {onces}, ended on a known vendor {vend_known} / unknown {vend_unknown}");
}
