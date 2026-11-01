// Userspace differential: map_kernel_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C of
// map_kernel.c (map_kernel_ref.c), on synthetic page-table objects. Every case runs both from the
// same random initial state and compares the return value, ALL table/variable bytes (including a pad
// after early_top_pgt / level4_kernel_pgt) and, in the AMD arm, every call made to the stub callees.
// Phase 1: startup_64_tables() (arbitrary _text/_end/CR4/cap/mask). Phase 2: the real __startup_64()
// wrapper, whose `lea sym(%rip)` / cap-byte / mask reads hit real symbols (map_kernel_syms.c).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs, clashing_extern_declarations)]
#[path = "MKRS"]
mod mk;
use std::ffi::c_void;

extern "C" {
    fn region_ptr(i: i32) -> *mut u8;
    fn region_len(i: i32) -> usize;
    fn region_off(i: i32) -> usize;
    fn snap_size() -> usize;
    fn snap(out: *mut u8);
    fn restore(inp: *const u8);
    fn log_reset();
    fn log_snap(out: *mut u64) -> usize;
    fn set_mask(m: u64);
    fn amd() -> i32;
    fn c_run(p2v: u64, bp: *mut c_void, text: u64, end: u64, cr4: u64, la57cap: i32, lo: u64, hi: u64) -> u64;
    static mut _text: [u8; 4096];
    static mut _end: [u8; 4096];
    static mut boot_cpu_data: [u8; 512];
    static mut g_cr4: u64;
}
#[cfg(CONFIG_AMD_MEM_ENCRYPT)]
extern "C" { static mut bss_dec: [u8; 8 << 20]; }

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}

fn tables() -> mk::Tables {
    unsafe {
        mk::Tables {
            early_dynamic_pgts: region_ptr(0).cast(), early_top_pgt: region_ptr(1).cast(),
            level4_kernel_pgt: region_ptr(2).cast(), level3_kernel_pgt: region_ptr(3).cast(),
            level2_fixmap_pgt: region_ptr(4).cast(), level2_kernel_pgt: region_ptr(5).cast(),
            next_early_pgt: region_ptr(6).cast(), phys_base: region_ptr(7).cast(),
            pgtable_l5_enabled: region_ptr(8).cast(), pgdir_shift: region_ptr(9).cast(), ptrs_per_p4d: region_ptr(10).cast(),
        }
    }
}
fn logs() -> Vec<u64> { let mut v = vec![0u64; 3 * 8192 + 3]; let n = unsafe { log_snap(v.as_mut_ptr()) }; v.truncate(n); v }

struct Case { p2v: u64, text: u64, end: u64, cr4: u64, cap: bool, mask: u64, lo: u64, hi: u64 }

fn gen(r: &mut Rng) -> Case {
    // p2v_offset: mostly 2M aligned (else the C hangs after writing phys_base)
    let mut p2v = match r.below(4) { 0 => 0, 1 => r.next() & !0x1f_ffff, 2 => (r.below(1 << 20) << 21).wrapping_neg(), _ => r.below(1 << 24) << 21 };
    if r.below(12) == 0 { p2v = p2v.wrapping_add(match r.below(4) { 0 => 1, 1 => 0x10_0000, 2 => 0x1f_ffff, _ => r.below(0x20_0000) }); }
    // _text: log-uniform below 2^46 mostly; sometimes 2^46..2^52 and above (hang / L5 limit)
    let bits = match r.below(40) { 0 => 46 + r.below(8), 1 => 64, _ => 12 + r.below(34) } as u32;
    let text = if bits >= 64 { r.next() } else { r.next() & ((1u64 << bits) - 1) };
    let text = if r.below(3) == 0 { text & !0x1f_ffff } else { text };
    // image size: 0, one page, up to 1 GiB-ish and sometimes a few GiB (<= ~2048 PMDs)
    let size = match r.below(8) { 6 => (r.below(512) << 21) + [0, 1, 2, 0x1f_ffff, 0x10_0000][r.below(5) as usize], 7 => (r.below(512) << 21).wrapping_sub(r.below(3)), 0 => 0, 1 => r.below(0x4000), 2 => r.below(1 << 30), 3 => (1 << 30) + r.below(0x40_0000), 4 => r.below(1 << 32), _ => r.below(64 << 20) };
    let end = text.wrapping_add(size);
    let cr4 = r.next() & !(1 << 12) | (r.below(2) << 12);
    let mask = if r.below(3) == 0 { 0 } else { 1u64 << (40 + r.below(13)) | if r.below(5) == 0 { r.below(0x1000) } else { 0 } };
    let lo = (r.next() & 0xffff_ffff_ffff) & !0xfff;
    let hi = match r.below(4) { 0 => lo, 1 => lo.wrapping_add(r.below(4) << 21), _ => lo.wrapping_add(r.below(40 << 21)) };
    Case { p2v, text, end, cr4, cap: r.below(4) == 0, mask, lo, hi }
}

fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|v| v.parse().ok()).unwrap_or(300_000);
    let nw: u64 = std::env::var("NW").ok().and_then(|v| v.parse().ok()).unwrap_or(30_000);
    let is_amd = unsafe { amd() } != 0;
    assert_eq!(is_amd, cfg!(CONFIG_AMD_MEM_ENCRYPT), "C and Rust arms must both be AMD or both not");
    let sz = unsafe { snap_size() };
    let mut r = Rng(0x9E3779B97F4A7C15);
    let pool: Vec<u8> = (0..(sz + (1 << 22))).map(|_| r.next() as u8).collect();
    let (mut init, mut sc, mut sr) = (vec![0u8; sz], vec![0u8; sz], vec![0u8; sz]);
    let (mut hang1, mut hang2, mut ok, mut l5, mut mask_runs, mut logged) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);

    let mut fresh = |r: &mut Rng, init: &mut Vec<u8>| {
        let off = (r.below(1 << 22) & !7) as usize;
        init.copy_from_slice(&pool[off..off + sz]);
        // biased words: zero / all-ones / present-only entries sprinkled in the tables
        for _ in 0..r.below(64) { let w = (r.below((sz / 8) as u64) * 8) as usize; let v = match r.below(4) { 0 => 0u64, 1 => u64::MAX, 2 => 1, _ => r.next() & !1 }; if w + 8 <= sz { init[w..w + 8].copy_from_slice(&v.to_le_bytes()); } }
        let put32 = |init: &mut Vec<u8>, i: i32, v: u32| { let o = unsafe { region_off(i) }; init[o..o + 4].copy_from_slice(&v.to_le_bytes()); };
        put32(init, 6, r.below(80) as u32);                       // next_early_pgt
        put32(init, 8, r.below(2) as u32);                        // __pgtable_l5_enabled
        put32(init, 9, if r.below(2) == 0 { 39 } else { 48 });    // pgdir_shift
        put32(init, 10, if r.below(2) == 0 { 1 } else { 512 });   // ptrs_per_p4d
    };

    // ---- phase 1: the core
    for _ in 0..n {
        let c = gen(&mut r);
        fresh(&mut r, &mut init);
        let bp = (r.next() | 1) as *mut c_void;
        unsafe {
            restore(init.as_ptr()); log_reset(); set_mask(c.mask);
            let rc = c_run(c.p2v, bp, c.text, c.end, c.cr4, c.cap as i32, c.lo, c.hi);
            snap(sc.as_mut_ptr()); let lc = logs();
            restore(init.as_ptr()); log_reset(); set_mask(c.mask);
            let t = tables();
            let m = mk::Machine { physaddr: c.text, end: c.end, cr4: c.cr4, cpu_has_la57: c.cap, me_mask: if is_amd { c.mask } else { 0 }, bss_decrypted: if is_amd { (c.lo, c.hi) } else { (0, 0) } };
            let rr = match mk::startup_64_tables(&t, &m, c.p2v, bp) { Ok(v) => v, Err(mk::Hang::AddressTooLarge) => 0xdead0001, Err(mk::Hang::NotPmdAligned) => 0xdead0002 };
            snap(sr.as_mut_ptr()); let lr = logs();
            if rc != rr || sc != sr || lc != lr {
                let first = sc.iter().zip(sr.iter()).position(|(a, b)| a != b);
                println!("MISMATCH phase1: p2v={:#x} text={:#x} end={:#x} cr4={:#x} cap={} mask={:#x} lo={:#x} hi={:#x}", c.p2v, c.text, c.end, c.cr4, c.cap, c.mask, c.lo, c.hi);
                println!("  ret C {rc:#x} Rust {rr:#x}; first differing byte {first:?}; logs equal {}", lc == lr);
                std::process::exit(1);
            }
            match rc { 0xdead0001 => hang1 += 1, 0xdead0002 => hang2 += 1, _ => { ok += 1; if c.cr4 & (1 << 12) != 0 { l5 += 1; } if is_amd && c.mask != 0 { mask_runs += 1; logged += (lc[0] > 0) as u64; } } }
        }
    }
    println!("phase 1 (core): {n} cases C == Rust (return, {} bytes of state{}): {ok} ran to the end ({l5} with CR4.LA57{}), {hang1} address-too-large, {hang2} not-2M-aligned",
             sz, if is_amd { ", every stub call" } else { "" }, if is_amd { format!(", {mask_runs} with an SME mask, {logged} made snp calls") } else { String::new() });

    // ---- phase 2: the real __startup_64() on real symbols
    let (mut w_ok, mut w_hang) = (0u64, 0u64);
    for _ in 0..nw {
        fresh(&mut r, &mut init);
        let cap = r.below(4) == 0; let cr4 = r.next() & !(1 << 12) | (r.below(2) << 12);
        let mask = if r.below(2) == 0 { 0 } else { 1u64 << (40 + r.below(13)) };
        let p2v = if r.below(10) == 0 { r.next() } else { r.next() & !0x1f_ffff };
        let (text, end) = unsafe { (_text.as_ptr() as u64, _end.as_ptr() as u64) };
        let bp = (r.next() | 1) as *mut c_void;
        #[cfg(CONFIG_AMD_MEM_ENCRYPT)]
        let (lo, hi) = unsafe { let b = bss_dec.as_ptr() as u64; (b, b + (6 << 20)) };
        #[cfg(not(CONFIG_AMD_MEM_ENCRYPT))]
        let (lo, hi) = (0, 0);
        unsafe {
            boot_cpu_data[mk::CAP_BYTE_INDEX] = cap as u8;
            restore(init.as_ptr()); log_reset(); set_mask(mask);
            let rc = c_run(p2v, bp, text, end, cr4, cap as i32, lo, hi);
            snap(sc.as_mut_ptr()); let lc = logs();
            restore(init.as_ptr()); log_reset(); set_mask(mask); g_cr4 = cr4;
            // the wrapper loops forever on the two hang conditions: skip those (phase 1 covered them)
            if rc == 0xdead0001 || rc == 0xdead0002 { w_hang += 1; continue; }
            let rr = mk::__startup_64(p2v, bp);
            snap(sr.as_mut_ptr()); let lr = logs();
            if rc != rr || sc != sr || lc != lr { println!("MISMATCH phase2: p2v={p2v:#x} cr4={cr4:#x} cap={cap} mask={mask:#x} ret C {rc:#x} Rust {rr:#x}"); std::process::exit(1); }
            w_ok += 1;
        }
    }
    println!("phase 2 (__startup_64 wrapper on real symbols): {nw} cases, {w_ok} compared C == Rust, {w_hang} skipped (hang conditions)");
}
