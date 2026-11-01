// Userspace differential: e820_rs.rs (included verbatim, linked against the REAL e820_glue.c wrappers) vs the REAL C
// of the pristine arch/x86/kernel/e820.c, on random e820 tables and random operation sequences.
//
// Both sides get byte-identical tables (all 4 + 20*EMAX bytes, stale entries beyond nr_entries included), run the same
// operation, and are compared on: the return value, ALL table bytes, pci_mem_start, userdef, max_mem_size and the
// complete printk log (level byte + formatted text of every record). The scratch arrays of the sanitiser are filled
// with DIFFERENT garbage on the two sides before every run (nothing may depend on stale scratch content).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs, clashing_extern_declarations, static_mut_refs)]
#[path = "E820RS"]
mod h;
use std::ffi::{c_char, c_void, CStr};

extern "C" {
    fn c_tbl(which: i32) -> *mut u8; fn c_tbl_size() -> usize; fn c_emax() -> u32;
    fn c_get_pci() -> u64; fn c_set_pci_mem_start(v: u64); fn c_userdef() -> i32; fn c_set_userdef(v: i32);
    fn c_scratch_fill(seed: u32);
    fn c_update_table(w: i32) -> i32; fn c_range_add(s: u64, z: u64, t: u32);
    fn c_range_update(s: u64, z: u64, o: u32, n: u32) -> u64;
    fn c_range_update_table(w: i32, s: u64, z: u64, o: u32, n: u32) -> u64;
    fn c_range_remove(s: u64, z: u64, o: u32, chk: i32) -> u64;
    fn c_mapped_any(s: u64, e: u64, t: u32) -> i32; fn c_mapped_raw_any(s: u64, e: u64, t: u32) -> i32;
    fn c_mapped_all(s: u64, e: u64, t: u32) -> i32; fn c_get_entry_type(s: u64, e: u64) -> i32;
    fn c_print_table(who: *mut c_char); fn c_update_table_print(); fn c_setup_pci_gap();
    fn c_end_of_ram_pfn() -> u64; fn c_end_of_low_ram_pfn() -> u64;
    fn c_memory_setup_default() -> *const c_char;
    fn c_parse_memopt(p: *mut c_char) -> i32; fn c_parse_memmap_opt(p: *mut c_char) -> i32;
    fn c_update_table_g(w: i32) -> i32; fn c_range_update_g(s: u64, z: u64, o: u32, n: u32) -> u64;

    fn g_tbl(which: i32) -> *mut u8; fn g_tbl_size() -> usize; fn g_emax() -> u32;
    fn g_set_pci_mem_start(v: u64); fn g_userdef() -> i32; fn g_set_userdef(v: i32); fn g_scratch_fill(seed: u32);
    fn g_update_table(w: i32) -> i32; fn g_range_update(s: u64, z: u64, o: u32, n: u32) -> u64;
    fn g_range_update_table(w: i32, s: u64, z: u64, o: u32, n: u32) -> u64;
    fn g_end_of_ram_pfn() -> u64; fn g_end_of_low_ram_pfn() -> u64;
    fn g_update_table_g(w: i32) -> i32; fn g_range_update_g(s: u64, z: u64, o: u32, n: u32) -> u64;

    fn log_side(s: i32); fn log_reset(); fn log_len(s: i32) -> usize; fn log_buf(s: i32) -> *const u8;
    fn set_boot_params(p: *const u8); fn set_max_pfn(v: u64); fn set_maxmem(v: u64);
    fn set_max_mem_size(v: u64); fn get_max_mem_size() -> u64; fn set_sort_mode(m: i32);
    fn bug_file() -> *const c_char; fn bug_line() -> i32;
    fn run_parse(f: unsafe extern "C" fn(*mut c_char) -> i32, p: *mut c_char) -> i32;
}
// pci_mem_start of the glue TU (read through the glue's own symbol, which h:: also uses)
extern "C" { static mut pci_mem_start: u64; }

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
    fn chance(&mut self, n: u64) -> bool { self.below(n) == 0 }
}

const TYPES: [u32; 14] = [1, 2, 3, 4, 5, 7, 12, 0xefff_ffff, 0, 6, 13, 128, 0xffff_ffff, 8];
const EDGE_A: [u64; 14] = [0, 1, 0xfff, 0x1000, 0x9f000, 0xa0000, 0x10_0000, 0xffff_ffff, 0x1_0000_0000,
    0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0xffff_ffff_ffff_f000, 0xffff_ffff_ffff_ffff, 0x3fff_ffff_ffff];
const EDGE_S: [u64; 12] = [0, 1, 2, 0xfff, 0x1000, 0x2000, 0x10_0000, 0x4000_0000, 0x8000_0000_0000_0000,
    0xffff_ffff_ffff_f000, 0xffff_ffff_ffff_ffff, 0x1_0000_0000];

#[derive(Clone, Copy)]
enum Mode { Dense, Realistic, Wide, Edge, Gap }

fn pick_type(r: &mut Rng) -> u32 {
    if r.chance(6) { return r.next() as u32; }
    if r.below(10) < 6 { return TYPES[r.below(5) as usize]; }
    TYPES[r.below(TYPES.len() as u64) as usize]
}
fn pick_addr(r: &mut Rng, m: Mode) -> u64 {
    match m {
        Mode::Dense => r.below(24) * 0x1000,
        Mode::Gap => r.below(48) * 0x40_0000,
        Mode::Realistic => match r.below(4) { 0 => r.below(0xa0) * 0x1000, 1 => 0x10_0000 + r.below(0x1000) * 0x1000,
            2 => 0x1_0000_0000 + r.below(0x4000) * 0x1_0000, _ => r.below(0xc000_0000) & !0xfff },
        Mode::Wide => if r.chance(4) { r.next() } else { r.next() >> r.below(40) },
        Mode::Edge => { let b = EDGE_A[r.below(EDGE_A.len() as u64) as usize]; b.wrapping_add(r.below(5).wrapping_sub(2)) }
    }
}
fn pick_size(r: &mut Rng, m: Mode) -> u64 {
    match m {
        Mode::Dense => r.below(12) * 0x1000,
        Mode::Gap => (1 + r.below(8)) * 0x40_0000,
        Mode::Realistic => match r.below(3) { 0 => r.below(0x100) * 0x1000, 1 => (1 + r.below(0x1000)) * 0x1_0000, _ => r.below(0x4000_0000) & !0xfff },
        Mode::Wide => if r.chance(5) { r.next() } else { r.next() >> r.below(50) },
        Mode::Edge => { let b = EDGE_S[r.below(EDGE_S.len() as u64) as usize]; b.wrapping_add(r.below(3).wrapping_sub(1)) }
    }
}

struct Image(Vec<u8>);
impl Image {
    fn new(sz: usize) -> Image { Image(vec![0; sz]) }
    fn set_nr(&mut self, n: u32) { self.0[0..4].copy_from_slice(&n.to_le_bytes()); }
    fn put(&mut self, i: usize, a: u64, s: u64, t: u32) {
        let o = 4 + 20 * i; self.0[o..o + 8].copy_from_slice(&a.to_le_bytes());
        self.0[o + 8..o + 16].copy_from_slice(&s.to_le_bytes()); self.0[o + 16..o + 20].copy_from_slice(&t.to_le_bytes());
    }
}
fn gen_table(r: &mut Rng, emax: usize, sz: usize) -> Image {
    let mut img = Image::new(sz);
    // stale garbage everywhere first (nothing may depend on it)
    if r.chance(2) { for b in img.0.iter_mut() { *b = r.next() as u8; } }
    let mode = match r.below(12) { 0..=3 => Mode::Dense, 4..=5 => Mode::Realistic, 6..=7 => Mode::Wide, 8..=9 => Mode::Gap, _ => Mode::Edge };
    let nr = match r.below(10) {
        0 => 0, 1 => 1, 2 => emax, 3 => emax.saturating_sub(1), 4 => emax.saturating_sub(r.below(4) as usize),
        _ => r.below(emax as u64 + 1) as usize };
    let nr = nr.min(emax);
    let mut cur = 0u64;
    for i in 0..nr {
        let (mut a, mut s) = (pick_addr(r, mode), pick_size(r, mode));
        if matches!(mode, Mode::Realistic) && r.below(3) != 0 { // mostly sorted, gapped
            a = cur.wrapping_add(pick_size(r, Mode::Dense)); s = pick_size(r, mode) & 0xffff_ffff; cur = a.wrapping_add(s);
        }
        if matches!(mode, Mode::Gap) { // sorted, non-overlapping, gaps and sizes in 4 MiB units (equal gaps, gap == the initial 4 MiB)
            a = cur.wrapping_add(r.below(4) * 0x40_0000); s = (1 + r.below(4)) * 0x40_0000; cur = a.wrapping_add(s);
        }
        if r.chance(7) && i > 0 && !matches!(mode, Mode::Gap) { // adjacency / duplicate of the previous entry's end
            let o = 4 + 20 * (i - 1);
            let pa = u64::from_le_bytes(img.0[o..o + 8].try_into().unwrap()); let ps = u64::from_le_bytes(img.0[o + 8..o + 16].try_into().unwrap());
            a = if r.chance(2) { pa.wrapping_add(ps) } else { pa }; if r.chance(2) { s = ps; }
        }
        img.put(i, a, s, pick_type(r));
    }
    img.set_nr(nr as u32);
    img
}

fn load(side: i32, which: i32, img: &Image) {
    unsafe { let p = if side == 0 { c_tbl(which) } else { g_tbl(which) }; std::ptr::copy_nonoverlapping(img.0.as_ptr(), p, img.0.len()); }
}
fn read(side: i32, which: i32, sz: usize) -> Vec<u8> {
    unsafe { let p = if side == 0 { c_tbl(which) } else { g_tbl(which) }; std::slice::from_raw_parts(p, sz).to_vec() }
}
fn log(side: i32) -> Vec<u8> { unsafe { std::slice::from_raw_parts(log_buf(side), log_len(side)).to_vec() } }
fn fmt_log(b: &[u8]) -> String { String::from_utf8_lossy(b).replace('\x02', "\n").replace('\x01', "<L>") }

#[derive(Default)]
struct Stats { ops: u64, per: [u64; 20], upd_neg1: u64, upd_changed: u64, upd_full: u64, upd_nonzero: u64, upd_merge: u64, upd_overlap: u64,
    rem_nonzero: u64, add_full: u64, upd_sz_nonzero: u64, mapped_true: u64, mapped_all_true: u64, gap_found: u64, gap_notfound: u64,
    setup_fallback: u64, setup_88: u64, setup_e801: u64, setup_e820: u64, parse_ok: u64, parse_err: u64, parse_userdef: u64,
    bugs: u64, log_bytes: u64, e2e_cnt: u64, spec_checked: u64 }

const OPN: [&str; 20] = ["update_table", "range_add", "range_update", "range_update_table", "range_remove", "mapped_any", "mapped_raw_any",
    "mapped_all", "get_entry_type", "print_table", "update_table_print", "setup_pci_gap", "end_of_ram_pfn", "end_of_low_ram_pfn",
    "memory_setup_default", "parse_memopt", "parse_memmap_opt", "bug_update_table", "bug_range_update", "tie_order"];

fn g_bug_reset() { }

/// The documented semantics of e820__update_table (independent of the algorithm): split at every distinct boundary,
/// each segment gets the highest type of the (non-empty) entries covering it, adjacent equal types merge unless
/// PRAM / SOFT_RESERVED, type 0 is a gap, the result is cut to `max` entries.
fn spec_update(ents: &[(u64, u64, u32)], max: usize) -> Vec<(u64, u64, u32)> {
    let live: Vec<(u128, u128, u32)> = ents.iter().filter(|e| e.1 != 0).map(|e| (e.0 as u128, e.0 as u128 + e.1 as u128, e.2)).collect();
    let mut pts: Vec<u128> = live.iter().flat_map(|e| [e.0, e.1]).collect(); pts.sort(); pts.dedup();
    let nomerge = |t: u32| t == 12 || t == 0xefff_ffff;
    let mut out: Vec<(u64, u64, u32)> = Vec::new();
    let mut cur: Option<(u128, u128, u32)> = None;
    for w in pts.windows(2) {
        let (lo, hi) = (w[0], w[1]);
        let t = live.iter().filter(|e| e.0 <= lo && lo < e.1).map(|e| e.2).max().unwrap_or(0);
        if t == 0 { if let Some(c) = cur.take() { out.push((c.0 as u64, (c.1 - c.0) as u64, c.2)); } continue; }
        match cur { Some(c) if c.2 == t && !nomerge(t) && c.1 == lo => cur = Some((c.0, hi, t)),
            _ => { if let Some(c) = cur.take() { out.push((c.0 as u64, (c.1 - c.0) as u64, c.2)); } cur = Some((lo, hi, t)); } }
    }
    if let Some(c) = cur.take() { out.push((c.0 as u64, (c.1 - c.0) as u64, c.2)); }
    out.truncate(max);
    out
}
fn table_entries(img: &[u8]) -> Vec<(u64, u64, u32)> {
    let nr = u32::from_le_bytes(img[0..4].try_into().unwrap()) as usize;
    (0..nr).map(|i| { let o = 4 + 20 * i; (u64::from_le_bytes(img[o..o + 8].try_into().unwrap()), u64::from_le_bytes(img[o + 8..o + 16].try_into().unwrap()), u32::from_le_bytes(img[o + 16..o + 20].try_into().unwrap())) }).collect()
}


/// EXH=1: every table of 2..=NMAX entries over a tiny domain (addresses 0..A, sizes 0..S, types {1,2,12}), through the
/// sanitiser on both sides and against the independent spec. No scratch refill: the scratch is garbage by construction.
fn exhaustive(emax: usize, sz: usize) {
    let ev = |k: &str, d: u64| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let (a_n, s_n) = (ev("A_N", 5), ev("S_N", 4)); let all_types = [1u32, 2, 12, 0xefff_ffff]; let types = &all_types[..ev("NT", 3) as usize];
    let nt = types.len(); let slots = (a_n * s_n) as usize * nt;
    let nmax: usize = std::env::var("NMAX").ok().and_then(|s| s.parse().ok()).unwrap_or(4).min(emax);
    let (mut total, mut changed, mut trunc) = (0u64, 0u64, 0u64);
    unsafe { c_scratch_fill(1); g_scratch_fill(2); log_reset(); }
    for n in 2..=nmax {
        let mut idx = vec![0usize; n];
        loop {
            let mut img = Image::new(sz); img.set_nr(n as u32);
            let mut ents = Vec::new();
            for (i, &k) in idx.iter().enumerate() {
                let (t, rest) = (types[k % types.len()], k / types.len());
                let (a, z) = (rest as u64 % a_n, rest as u64 / a_n);
                img.put(i, a, z, t); ents.push((a, z, t));
            }
            for side in 0..2 { load(side, 0, &img); }
            let (rc, rg) = unsafe { log_side(0); let a = c_update_table(0); log_side(1); let b = g_update_table(0); (a, b) };
            let (ta, tb) = (read(0, 0, sz), read(1, 0, sz));
            if rc != rg || ta != tb { fail(format!("EXH n={n} {:x?}: ret C {rc} Rust {rg}; C {:x?} Rust {:x?}", ents, table_entries(&ta), table_entries(&tb))); }
            let want = spec_update(&ents, emax); let got = table_entries(&ta);
            if rc == 0 && want != got { fail(format!("EXH n={n} {:x?}: SPEC {:x?} != got {:x?}", ents, want, got)); }
            if rc != 0 { fail(format!("EXH n={n} {:x?}: unexpected -1", ents)); }
            total += 1; if ta != img.0 { changed += 1 } if want.len() == emax { trunc += 1 }
            // next
            let mut k = 0; loop { if k == n { break; } idx[k] += 1; if idx[k] < slots { break; } idx[k] = 0; k += 1; }
            if k == n { break; }
        }
    }
    println!("e820_cmp EXH: EMAX={emax}, every table of 2..={nmax} entries over addr 0..{a_n} x size 0..{s_n} x {nt} types: {total} tables, C == Rust (return value + all {sz} bytes) and == the independent spec on every one; table changed by the sanitiser {changed}; result reached the max-entries cut {trunc}");
}

fn fail(msg: String) -> ! { eprintln!("MISMATCH: {msg}"); std::process::exit(1); }

fn pick_range(r: &mut Rng, img: &[u8]) -> (u64, u64) {
    // sometimes derive the range from an existing entry so partial / complete / interior coverage all happen
    let nr = u32::from_le_bytes(img[0..4].try_into().unwrap()) as usize;
    let emax = (img.len() - 4) / 20;
    let m = match r.below(4) { 0 => Mode::Dense, 1 => Mode::Wide, 2 => Mode::Edge, _ => Mode::Realistic };
    if nr > 0 && nr <= emax && r.below(3) == 0 {
        let i = r.below(nr as u64) as usize; let o = 4 + 20 * i;
        let a = u64::from_le_bytes(img[o..o + 8].try_into().unwrap()); let s = u64::from_le_bytes(img[o + 8..o + 16].try_into().unwrap());
        return match r.below(6) {
            0 => (a, s), 1 => (a.wrapping_add(r.below(s.min(1 << 20).max(1))), r.below(s.min(1 << 20).max(1))),
            2 => (a.wrapping_sub(r.below(0x3000)), s.wrapping_add(r.below(0x6000))), 3 => (a.wrapping_add(s), pick_size(r, m)),
            4 => (a.wrapping_sub(pick_size(r, m) & 0xfff_ffff), pick_size(r, m)), _ => (a, r.below(s.min(1 << 24).max(1))) };
    }
    (pick_addr(r, m), pick_size(r, m))
}

fn parse_string(r: &mut Rng) -> Vec<u8> {
    let sizes = ["0", "1", "4", "16", "0x1000", "0x100000", "1K", "512k", "1M", "64m", "2G", "1g", "3T", "1P", "1E", "0x10M", "010", "0x", "0xG", "", "7z",
        "18446744073709551615", "18446744073709551616", "0xffffffffffffffff", "4096", "64M", "128M", "0x7fffffff", "99999999999999999999", "-1", " 1", "268", "4294967297", "4294967308", "0x10c", "0x100000003", "256"];
    let seps = ["@", "#", "$", "!", "%", "", "", "@", "@", "?", "*"];
    let mut s = String::new();
    let items = 1 + r.below(4);
    for k in 0..items {
        if k > 0 { s.push(','); }
        match r.below(14) {
            0 => s.push_str("exactmap"), 1 => s.push_str("exactmapx"), 2 => s.push_str("exact"), 3 => s.push_str("nopentium"), 4 => s.push_str(""),
            _ => {
                s.push_str(sizes[r.below(sizes.len() as u64) as usize]);
                let sep = seps[r.below(seps.len() as u64) as usize]; s.push_str(sep);
                if sep == "%" { // %start-from+to
                    s.push_str(sizes[r.below(sizes.len() as u64) as usize]);
                    match r.below(5) { 0 => { s.push('-'); s.push_str(["1", "2", "3", "4", "7", "12", "5", "0", "0x7", "x", "268", "4294967297", "4294967308", "0x10c", "256", "0x100000007"][r.below(16) as usize]); }
                        1 => { s.push('+'); s.push_str(["1", "2", "3", "4", "7", "12", "5", "0", "0x7", "x", "268", "4294967297", "4294967308", "0x10c", "256", "0x100000007"][r.below(16) as usize]); }
                        2 => { s.push('-'); s.push_str(["1", "2", "3"][r.below(3) as usize]); s.push('+'); s.push_str(["1", "2", "3", "12"][r.below(4) as usize]); }
                        3 => { s.push('-'); s.push_str(["1", "2"][r.below(2) as usize]); s.push('-'); s.push('1'); } _ => {} }
                } else if sep != "" { s.push_str(sizes[r.below(sizes.len() as u64) as usize]); }
                if r.chance(9) { s.push_str(["x", "zz", " ", "@", "%", "-", "+"][r.below(7) as usize]); }
            }
        }
    }
    let mut v = s.into_bytes();
    if r.chance(6) && !v.is_empty() { let i = r.below(v.len() as u64) as usize; v[i] = (r.next() as u8) | 1; if v[i] == 0 { v[i] = b'x'; } for b in v.iter_mut() { if *b == 0 { *b = b'q'; } } }
    v
}

fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(30_000);
    let seed: u64 = std::env::var("SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x1234_5678_9abc_def1);
    let tie = std::env::var("TIE").is_ok();     // Rust runs with the stable insertion sort, C with the kernel heapsort
    let mut r = Rng(seed);
    let (emax, sz) = unsafe { assert_eq!(c_emax(), g_emax()); assert_eq!(c_tbl_size(), g_tbl_size()); (c_emax() as usize, c_tbl_size()) };
    if let Ok(c) = std::env::var("CASE") {   // CASE="addr,size,type;addr,size,type" (hex or decimal): run the sanitiser on exactly that table
        let ents: Vec<(u64, u64, u32)> = c.split(';').map(|e| { let v: Vec<&str> = e.split(',').collect(); let p = |x: &str| if let Some(h) = x.trim().strip_prefix("0x") { u64::from_str_radix(h, 16).unwrap() } else { x.trim().parse().unwrap() }; (p(v[0]), p(v[1]), p(v[2]) as u32) }).collect();
        let mut img = Image::new(sz); img.set_nr(ents.len() as u32); for (i, e) in ents.iter().enumerate() { img.put(i, e.0, e.1, e.2); }
        for side in 0..2 { load(side, 0, &img); }
        let (rc, rg) = unsafe { log_side(0); let a = c_update_table(0); log_side(1); let b = g_update_table(0); (a, b) };
        println!("C rc={rc} {:x?}\nRust rc={rg} {:x?}\nspec {:x?}", table_entries(&read(0, 0, sz)), table_entries(&read(1, 0, sz)), spec_update(&ents, emax));
        return;
    }
    if std::env::var("EXH").is_ok() { exhaustive(emax, sz); return; }
    let mut st = Stats::default();
    let (mut sc_c, mut sc_g) = (1u32, 1000u32);
    for case in 0..n {
        let img = gen_table(&mut r, emax, sz);
        let kx = gen_table(&mut r, emax, sz);
        let fw = gen_table(&mut r, emax, sz);
        for side in 0..2 { load(side, 0, &img); load(side, 1, &kx); load(side, 2, &fw); }
        let ud0 = (r.below(3) == 0) as i32; let pm0 = r.next();
        unsafe { c_set_userdef(ud0); g_set_userdef(ud0); c_set_pci_mem_start(pm0); g_set_pci_mem_start(pm0); }
        let nops = 1 + r.below(6);
        for _ in 0..nops {
            let cur = read(0, 0, sz);
            let which = match r.below(8) { 0 => 1, 1 => 2, _ => 0 };
            let opn = r.below(19) as usize;
            // op parameters (drawn once, used by both sides)
            let (s1, z1) = pick_range(&mut r, &cur);
            let ty = pick_type(&mut r); let ty2 = pick_type(&mut r);
            let chk = r.chance(2) as i32; let e2 = s1.wrapping_add(z1);
            let who_s: &CStr = [c"BIOS-e820", c"user", c"modified", c"extended", c"x"][r.below(5) as usize];
            let mut who_a = who_s.to_bytes_with_nul().to_vec(); let mut who_b = who_a.clone();
            let mpfn = match r.below(4) { 0 => r.below(0x1000_0000), 1 => r.next() >> 12, 2 => r.below(0x10_0000), _ => 0x7fff_ffff };
            let maxmem = [1u64 << 46, 1u64 << 52, 1 << 32, 0x1000, r.next() >> 8][r.below(5) as usize];
            let mut bp = vec![0u8; 4096];
            for b in bp.iter_mut() { *b = if r.chance(3) { r.next() as u8 } else { 0 }; }
            let nbp = match r.below(8) { 0 => 0, 1 => 1, 2 => 2, 3 => 128, _ => r.below(129) } as usize;
            bp[0x1e8] = nbp as u8;
            for i in 0..128usize {
                let o = 0x2d0 + 20 * i; let m = match r.below(4) { 0 => Mode::Dense, 1 => Mode::Edge, 2 => Mode::Wide, _ => Mode::Realistic };
                let (a, s) = (pick_addr(&mut r, m), pick_size(&mut r, m)); let t = pick_type(&mut r);
                bp[o..o + 8].copy_from_slice(&a.to_le_bytes()); bp[o + 8..o + 16].copy_from_slice(&s.to_le_bytes()); bp[o + 16..o + 20].copy_from_slice(&t.to_le_bytes());
            }
            if r.chance(2) { bp[0x1e0..0x1e4].copy_from_slice(&(r.next() as u32 & 0xfff_ffff).to_le_bytes()); bp[2..4].copy_from_slice(&(r.next() as u16).to_le_bytes()); }
            let str_in = if opn >= 15 { Some(parse_string(&mut r)) } else { None };
            let null_str = r.chance(40);
            let tie_case = tie && opn == 0;
            let _ = tie_case;

            // fresh scratch garbage, different on the two sides
            sc_c = sc_c.wrapping_add(1); sc_g = sc_g.wrapping_add(7);
            unsafe { c_scratch_fill(sc_c); g_scratch_fill(sc_g); set_boot_params(bp.as_ptr()); set_max_pfn(mpfn); set_maxmem(maxmem); }
            let mut ret = [0i128; 2]; let mut ss = [String::new(), String::new()]; let mut bugs: [(String, i32); 2] = [(String::new(), 0), (String::new(), 0)];
            let mut hp = [0u64; 2];
            let mut st_c: i64 = 0;
            let _ = &mut st_c;
            unsafe {
                log_reset();
                for side in 0..2i32 {
                    log_side(side);
                    set_max_mem_size(0xdead_beef_0000_0000u64 ^ (opn as u64));
                    if side == 1 { set_sort_mode(if tie { 1 } else { 0 }); } else { set_sort_mode(0); }
                    let c = side == 0;
                    let sp = |v: &mut Vec<u8>| v.as_mut_ptr() as *mut c_char;
                    match opn {
                        0 => ret[side as usize] = if c { c_update_table(which) } else { g_update_table(which) } as i128,
                        1 => if c { c_range_add(s1, z1, ty) } else { h::e820__range_add(s1, z1, ty) },
                        2 => { let (o, nw) = if ty == ty2 { (ty, ty.wrapping_add(1)) } else { (ty, ty2) };
                               ret[side as usize] = if c { c_range_update(s1, z1, o, nw) } else { g_range_update(s1, z1, o, nw) } as i128; }
                        3 => { let (o, nw) = if ty == ty2 { (ty, ty.wrapping_add(1)) } else { (ty, ty2) };
                               ret[side as usize] = if c { c_range_update_table(which, s1, z1, o, nw) } else { g_range_update_table(which, s1, z1, o, nw) } as i128; }
                        4 => ret[side as usize] = if c { c_range_remove(s1, z1, ty, chk) } else { h::e820__range_remove(s1, z1, ty, chk != 0) } as i128,
                        5 => ret[side as usize] = if c { c_mapped_any(s1, e2, ty) } else { h::e820__mapped_any(s1, e2, ty) as i32 } as i128,
                        6 => ret[side as usize] = if c { c_mapped_raw_any(s1, e2, ty) } else { h::e820__mapped_raw_any(s1, e2, ty) as i32 } as i128,
                        7 => ret[side as usize] = if c { c_mapped_all(s1, e2, ty) } else { h::e820__mapped_all(s1, e2, ty) as i32 } as i128,
                        8 => ret[side as usize] = if c { c_get_entry_type(s1, e2) } else { h::e820__get_entry_type(s1, e2) } as i128,
                        9 => if c { c_print_table(sp(&mut who_a)) } else { h::e820__print_table(sp(&mut who_b)) },
                        10 => if c { c_update_table_print() } else { h::e820__update_table_print() },
                        11 => if c { c_setup_pci_gap() } else { h::e820__setup_pci_gap() },
                        12 => ret[side as usize] = if c { c_end_of_ram_pfn() } else { g_end_of_ram_pfn() } as i128,
                        13 => ret[side as usize] = if c { c_end_of_low_ram_pfn() } else { g_end_of_low_ram_pfn() } as i128,
                        14 => { let w = if c { c_memory_setup_default() } else { h::e820__memory_setup_default() as *const c_char };
                                ss[side as usize] = CStr::from_ptr(w).to_string_lossy().into_owned(); }
                        15 | 16 => {
                            let mut buf = str_in.clone().unwrap(); buf.push(0);
                            let p = if null_str && opn == 15 { std::ptr::null_mut() } else { buf.as_mut_ptr() as *mut c_char };
                            let f: unsafe extern "C" fn(*mut c_char) -> i32 = if opn == 15 { if c { c_parse_memopt } else { h::parse_memopt } } else { if c { c_parse_memmap_opt } else { h::parse_memmap_opt } };
                            g_bug_reset();
                            ret[side as usize] = run_parse(f, p) as i128;
                            if ret[side as usize] == -99 { bugs[side as usize] = (CStr::from_ptr(bug_file()).to_string_lossy().into_owned(), bug_line()); }
                            ss[side as usize] = String::from_utf8_lossy(&buf).into_owned();
                        }
                        17 => { // BUG_ON(nr_entries > max) in e820__update_table: force the table over the limit
                            let p = if c { c_tbl(which) } else { g_tbl(which) }; let saved = std::slice::from_raw_parts(p, sz).to_vec();
                            (p as *mut u32).write(emax as u32 + 1);
                            ret[side as usize] = if c { c_update_table_g(which) } else { g_update_table_g(which) } as i128;
                            std::ptr::copy_nonoverlapping(saved.as_ptr(), p, sz);
                            bugs[side as usize] = (CStr::from_ptr(bug_file()).to_string_lossy().into_owned(), bug_line());
                        }
                        18 => { // BUG_ON(old == new)
                            ret[side as usize] = if c { c_range_update_g(s1, z1, ty, ty) } else { g_range_update_g(s1, z1, ty, ty) } as i128;
                            bugs[side as usize] = (CStr::from_ptr(bug_file()).to_string_lossy().into_owned(), bug_line());
                        }
                        _ => unreachable!(),
                    }
                    hp[side as usize] = get_max_mem_size();
                }
            }
            // r.below(1) above consumed no entropy difference between sides (both are in the same loop body); keep deterministic
            let (ta, tb) = (read(0, 0, sz), read(1, 0, sz));
            let (ka, kb) = (read(0, 1, sz), read(1, 1, sz)); let (fa, fb) = (read(0, 2, sz), read(1, 2, sz));
            let (la, lb) = (log(0), log(1));
            let (pa, pb) = unsafe { (c_get_pci(), pci_mem_start) };
            let (ua, ub) = unsafe { (c_userdef(), g_userdef()) };
            let ctx = || format!("case {case} op {} ({}), which {which}, s1={s1:#x} z1={z1:#x} e2={e2:#x} ty={ty:#x}/{ty2:#x} chk={chk} str={:?}", opn, OPN[opn], str_in.as_ref().map(|v| String::from_utf8_lossy(v).into_owned()));
            let dump2 = || { let t = read(1, 0, sz); format!("rust table nr={} first={:02x?}", u32::from_le_bytes(t[0..4].try_into().unwrap()), &t[0..24]) };
            let dump = || { let nr = u32::from_le_bytes(cur[0..4].try_into().unwrap()) as usize; (0..nr.min(emax)).map(|i| { let o = 4 + 20 * i; format!("[{:#x}+{:#x} t{:#x}]", u64::from_le_bytes(cur[o..o+8].try_into().unwrap()), u64::from_le_bytes(cur[o+8..o+16].try_into().unwrap()), u32::from_le_bytes(cur[o+16..o+20].try_into().unwrap())) }).collect::<Vec<_>>().join(" ") };
            if ret[0] != ret[1] { fail(format!("{}: return C {} Rust {}\n  table before: {}\n  {}", ctx(), ret[0], ret[1], dump(), dump2())); }
            if ss[0] != ss[1] { fail(format!("{}: string C {:?} Rust {:?}", ctx(), ss[0], ss[1])); }
            if bugs[0] != bugs[1] { fail(format!("{}: BUG site C {:?} Rust {:?}", ctx(), bugs[0], bugs[1])); }
            if hp[0] != hp[1] { fail(format!("{}: max_mem_size C {:#x} Rust {:#x}", ctx(), hp[0], hp[1])); }
            if pa != pb { fail(format!("{}: pci_mem_start C {pa:#x} Rust {pb:#x}", ctx())); }
            if ua != ub { fail(format!("{}: userdef C {ua} Rust {ub}", ctx())); }
            for (nm, a, b) in [("table", &ta, &tb), ("kexec", &ka, &kb), ("firmware", &fa, &fb)] {
                if a != b { let i = a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap();
                    fail(format!("{}: {nm} bytes differ at {i} (C {:#x} Rust {:#x}); nr C {} Rust {}", ctx(), a[i], b[i],
                        u32::from_le_bytes(a[0..4].try_into().unwrap()), u32::from_le_bytes(b[0..4].try_into().unwrap()))); } }
            if opn == 0 && which == 0 && ret[0] == 0 {
                let want = spec_update(&table_entries(&cur), emax);
                let got = table_entries(&ta);
                if want != got { fail(format!("{}: SPEC differs from both C and Rust\n  spec {:x?}\n  got  {:x?}\n  before {:x?}", ctx(), want, got, table_entries(&cur))); }
                st.spec_checked += 1;
            }
            if la != lb { fail(format!("{}: printk log differs\n--- C ---\n{}--- Rust ---\n{}", ctx(), fmt_log(&la), fmt_log(&lb))); }
            // statistics (evidence that the interesting paths ran)
            st.ops += 1; st.per[opn] += 1; st.log_bytes += la.len() as u64;
            let nr_before = u32::from_le_bytes(cur[0..4].try_into().unwrap()); let nr_after = u32::from_le_bytes(ta[0..4].try_into().unwrap());
            match opn {
                0 => { if ret[0] == -1 { st.upd_neg1 += 1 } else if which == 0 { if ta != cur { st.upd_changed += 1 } if nr_before as usize == emax { st.upd_full += 1 } if nr_after < nr_before { st.upd_merge += 1 } } }
                1 => if nr_before as usize >= emax && nr_after == nr_before { st.add_full += 1 },
                2 | 3 => if ret[0] != 0 { st.upd_sz_nonzero += 1 },
                4 => if ret[0] != 0 { st.rem_nonzero += 1 },
                5 | 6 => if ret[0] != 0 { st.mapped_true += 1 },
                7 | 8 => if ret[0] != 0 && !(opn == 8 && ret[0] == -22) { st.mapped_all_true += 1 },
                11 => if String::from_utf8_lossy(&la).contains("Cannot find") { st.gap_notfound += 1 } else { st.gap_found += 1 },
                14 => { st.setup_fallback += (ss[0] != "BIOS-e820") as u64; st.setup_88 += (ss[0] == "BIOS-88") as u64; st.setup_e801 += (ss[0] == "BIOS-e801") as u64; st.setup_e820 += (ss[0] == "BIOS-e820") as u64; }
                15 | 16 => { if ret[0] == 0 { st.parse_ok += 1 } else { st.parse_err += 1 } if ud0 == 0 && ua != 0 { st.parse_userdef += 1 } }
                17 | 18 => if bugs[0].1 != 0 { st.bugs += 1 },
                _ => {}
            }
            let _ = (st.upd_nonzero, st.upd_overlap, st.e2e_cnt);
        }
    }
    println!("e820_cmp: EMAX={emax} N={n} cases, {} operations, C == Rust on every one (return value, all {} table bytes x3 tables, pci_mem_start, userdef, max_mem_size, printk log {} bytes)", st.ops, sz, st.log_bytes);
    for (i, nm) in OPN.iter().enumerate() { if st.per[i] > 0 { print!("{nm}={} ", st.per[i]); } }
    println!();
    println!("  coverage: update_table -1 returns {}, changed-table {}, merged/shrunk {}, run on a FULL table {}; range_add on full table {}; range update/remove with nonzero size {}/{}; mapped_* true {}/{}; gap found/not-found {}/{}; memory_setup e820/88/e801 {}/{}/{}; parse ok/err {}/{}; BUG sites compared {}; sanitiser results also checked against the independent spec {}",
        st.upd_neg1, st.upd_changed, st.upd_merge, st.upd_full, st.add_full, st.upd_sz_nonzero, st.rem_nonzero, st.mapped_true, st.mapped_all_true, st.gap_found, st.gap_notfound, st.setup_e820, st.setup_88, st.setup_e801, st.parse_ok, st.parse_err, st.bugs, st.spec_checked);
    if tie { println!("  (TIE mode: the Rust side used a stable insertion sort, the C side the kernel heapsort)"); }
}
