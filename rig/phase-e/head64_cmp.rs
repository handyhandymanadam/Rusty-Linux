// Userspace differential: head64_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C of the early
// page-fault group of head64.c (head64_ref.c), on synthetic early page tables. Every case runs both from the
// same state and compares the return value, ALL table/variable bytes and the log of every call made outside
// the tables (write_cr3, read of CR2, the vc/ve/fixup hooks with their arguments).
// The tables are built so that every present-looking entry is a valid encoded pointer to one of the 64 early
// tables (the C dereferences them): entry = (table - __START_KERNEL_map + phys_base) | flags.
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs, clashing_extern_declarations)]
#[path = "H64RS"]
mod h;
use std::ffi::c_void;

extern "C" {
    fn region_ptr(i: i32) -> *mut u8;
    fn region_off(i: i32) -> usize;
    fn snap_size() -> usize;
    fn snap(out: *mut u8);
    fn restore(inp: *const u8);
    fn log_reset();
    fn log_snap(out: *mut u64) -> usize;
    fn set_inputs(cr2: u64, vc: i32, ve: i32);
    fn amd() -> i32;
    fn c_make_pgtable(a: u64, pmd: u64) -> bool;
    fn c_reset();
    fn c_exception(r: *mut c_void, t: i32);
    fn c_pa_nodebug(x: u64) -> u64;
    fn c_read_cr3_pa() -> u64;
    fn sim_write_cr3(v: u64);
    fn sim_read_cr2() -> u64;
    fn sim_vc(r: *mut c_void) -> bool;
    fn sim_ve(r: *mut c_void) -> bool;
    fn sim_fixup(r: *mut c_void, t: i32);
}

struct Sim;
impl h::Cr3 for Sim { fn write_cr3(&mut self, v: u64) { unsafe { sim_write_cr3(v) } } }
impl h::Exc for Sim {
    fn read_cr2(&mut self) -> u64 { unsafe { sim_read_cr2() } }
    fn vc(&mut self, r: *mut c_void) -> bool { unsafe { sim_vc(r) } }
    fn ve(&mut self, r: *mut c_void) -> bool { unsafe { sim_ve(r) } }
    fn fixup(&mut self, r: *mut c_void, t: i32) { unsafe { sim_fixup(r, t) } }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}
const START: u64 = 0xffff_ffff_8000_0000;
// region indexes (head64_ref.c R[])
const R_DYN: i32 = 0; const R_TOP: i32 = 1; const R_NEXT: i32 = 2; const R_PMDF: i32 = 3; const R_PB: i32 = 4;
const R_L5: i32 = 5; const R_SHIFT: i32 = 6; const R_P4D: i32 = 7; const R_PO: i32 = 8; const R_CR3: i32 = 9; const R_ME: i32 = 10;

fn env(is_amd: bool) -> h::Env {
    unsafe {
        let r32 = |i| (region_ptr(i) as *const u32).read();
        let r64 = |i| (region_ptr(i) as *const u64).read();
        h::Env {
            early_top_pgt: region_ptr(R_TOP).cast(), early_dynamic_pgts: region_ptr(R_DYN).cast(),
            next_early_pgt: region_ptr(R_NEXT).cast(), early_pmd_flags: r64(R_PMDF), phys_base: r64(R_PB),
            l5: r32(R_L5) != 0, pgdir_shift: r32(R_SHIFT), ptrs_per_p4d: r32(R_P4D), page_offset: r64(R_PO),
            me_mask: if is_amd { r64(R_ME) } else { 0 }, physical_mask: ((1u64 << 52) - 1) & !(if is_amd { r64(R_ME) } else { 0 }), cr3: r64(R_CR3),
        }
    }
}
fn logs() -> Vec<u64> { let mut v = vec![0u64; 3 * 4096 + 1]; let n = unsafe { log_snap(v.as_mut_ptr()) }; v.truncate(n); v }

/// Build a random consistent state in `init` (a snapshot blob). Returns (address-ish bias info).
fn fresh(r: &mut Rng, init: &mut Vec<u8>, is_amd: bool) {
    let (a_dyn, t) = unsafe { (region_ptr(R_DYN) as u64, region_ptr(R_TOP) as u64) };
    let put = |init: &mut Vec<u8>, i: i32, b: &[u8]| { let o = unsafe { region_off(i) }; init[o..o + b.len()].copy_from_slice(b); };
    let l5 = r.below(2) == 1;
    let (shift, p4d): (u32, u32) = match r.below(10) { 0 => (if l5 { 39 } else { 48 }, if l5 { 1 } else { 1 }), _ => (if l5 { 48 } else { 39 }, if l5 { 512 } else { 1 }) };
    let po = match r.below(10) { 0..=3 => 0xffff_8880_0000_0000u64, 4..=6 => 0xff11_0000_0000_0000, 7 => 0, 8 => r.next() & !0xfff, _ => 0xffff_8880_0000_0000u64.wrapping_add(r.below(1 << 30) << 12) };
    let pbase = r.below(1 << 19) << 21;                       // P: physical base of the early tables
    let phys_base = START.wrapping_sub(a_dyn).wrapping_add(pbase);
    let mask = if is_amd && r.below(2) == 0 { 1u64 << (40 + r.below(13)) } else { 0 };
    let pmdf = match r.below(3) { 0 => 0x1e3 & !((1u64 << 8) | (1 << 63)), 1 => r.next(), _ => r.next() & 0xfff };
    // tables: each entry empty or an encoded pointer to table k with random flags
    let enc = |r: &mut Rng| -> u64 { if r.below(3) == 0 { 0 } else { ((4096 * r.below(64) + pbase) | r.below(0x1000) | (r.below(2) << 63)) } };
    let dyn_o = unsafe { region_off(R_DYN) }; let top_o = unsafe { region_off(R_TOP) };
    for i in 0..(64 * 512) { let v = enc(r); init[dyn_o + i * 8..dyn_o + i * 8 + 8].copy_from_slice(&v.to_le_bytes()); }
    for i in 0..512 { let v = enc(r); init[top_o + i * 8..top_o + i * 8 + 8].copy_from_slice(&v.to_le_bytes()); }
    let next = if r.below(4) == 0 { r.below(80) as u32 } else { r.below(64) as u32 };
    // cr3: usually the value the C expects, so the tables are used; sometimes not
    let pa = {
        // the C's __pa_nodebug(early_top_pgt) under this state: uses phys_base / page_offset (see Env::pa_nodebug)
        let y = t.wrapping_sub(START);
        y.wrapping_add(if t > y { phys_base } else { START.wrapping_sub(po) })
    };
    let cr3 = match r.below(10) { 0 => r.next(), 1 => pa.wrapping_add(4096), _ => (pa & 0x000f_ffff_ffff_f000) | r.below(0x1000) | (r.below(2) << 63) };
    put(init, R_NEXT, &next.to_le_bytes()); put(init, R_PMDF, &pmdf.to_le_bytes()); put(init, R_PB, &phys_base.to_le_bytes());
    put(init, R_L5, &(l5 as u32).to_le_bytes()); put(init, R_SHIFT, &shift.to_le_bytes()); put(init, R_P4D, &(p4d as u32).to_le_bytes());
    put(init, R_PO, &po.to_le_bytes()); put(init, R_CR3, &cr3.to_le_bytes());
    if is_amd { put(init, R_ME, &mask.to_le_bytes()); }
    let _ = (l5, shift);
}
fn address(r: &mut Rng, init: &[u8]) -> u64 {
    let o = unsafe { region_off(R_PO) }; let po = u64::from_le_bytes(init[o..o + 8].try_into().unwrap());
    match r.below(8) {
        0 => r.next(),
        1 => po.wrapping_add(r.next() >> (12 + r.below(30))),
        2 => po.wrapping_add(1u64 << (45 + r.below(9))).wrapping_add(r.below(1 << 30)),   // around MAXMEM
        3 => po.wrapping_add((1u64 << 46) - r.below(3)),
        4 => po.wrapping_add((1u64 << 52) - r.below(3)),
        _ => po.wrapping_add(r.below(1 << 40)),
    }
}

fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|v| v.parse().ok()).unwrap_or(200_000);
    let is_amd = unsafe { amd() } != 0;
    assert_eq!(is_amd, cfg!(CONFIG_AMD_MEM_ENCRYPT), "C and Rust arms must both be AMD or both not");
    let sz = unsafe { snap_size() };
    let mut r = Rng(0x9E3779B97F4A7C15);
    let (mut init, mut sc, mut sr) = (vec![0u8; sz], vec![0u8; sz], vec![0u8; sz]);
    let (mut ok_true, mut ok_false, mut resets, mut pf_true, mut dispatch) = (0u64, 0u64, 0u64, 0u64, [0u64; 4]);
    let mut l5_true = 0u64;
    let mut rr_reset = 0u64;

    for case in 0..n {
        fresh(&mut r, &mut init, is_amd);
        let addr = address(&mut r, &init);
        let pmd = r.next();
        let mode = r.below(4);   // 0: make_pgtable, 1: early_make via exception, 2: reset, 3: exception any trap
        let trap = match r.below(10) { 0..=5 => 14, 6 => 29, 7 => 20, _ => r.below(32) as i32 };
        let (vc, ve) = (r.below(2) as i32, r.below(2) as i32);
        let regs = (r.next() | 8) as *mut c_void;
        // ---- C
        let (rc, sc_log);
        unsafe {
            restore(init.as_ptr()); log_reset(); set_inputs(addr, vc, ve);
            let mut b = 0u8;
            match mode { 0 => b = c_make_pgtable(addr, pmd) as u8, 2 => c_reset(), _ => c_exception(regs, if mode == 1 { 14 } else { trap }) }
            rc = b; snap(sc.as_mut_ptr()); sc_log = logs();
        }
        // ---- Rust
        let (rr, sr_log);
        unsafe {
            restore(init.as_ptr()); log_reset(); set_inputs(addr, vc, ve);
            let e = env(is_amd); let mut s = Sim; let mut b = 0u8;
            match mode {
                0 => b = h::make_pgtable(&e, &mut s, addr, pmd) as u8,
                2 => h::reset_tables(&e, &mut s),
                _ => h::early_exception(&e, &mut s, regs, if mode == 1 { 14 } else { trap }, is_amd, true),
            }
            rr = b; snap(sr.as_mut_ptr()); sr_log = logs();
        }
        if rc != rr || sc != sr || sc_log != sr_log {
            let first = sc.iter().zip(sr.iter()).position(|(a, b)| a != b);
            println!("MISMATCH case {case} mode {mode} addr={addr:#x} pmd={pmd:#x} trap={trap}: ret C {rc} Rust {rr}; first differing byte {first:?}; logs equal {} ({} vs {} entries)", sc_log == sr_log, sc_log.len(), sr_log.len());
            std::process::exit(1);
        }
        if mode == 0 { if rc != 0 { ok_true += 1; } else { ok_false += 1; } }
        if sc_log.chunks(3).skip(0).any(|c| c[0] == 1) { resets += 1; }
        if mode == 2 { rr_reset += 1; }
        if mode == 1 && sc_log.len() > 1 && !sc_log[1..].chunks(3).any(|c| c[0] == 5) { pf_true += 1; }
        if mode == 3 { dispatch[match trap { 14 => 0, 29 => 1, 20 => 2, _ => 3 }] += 1; }
        if mode == 0 && rc != 0 && init[unsafe { region_off(R_L5) }] != 0 { l5_true += 1; }
    }
    // ---- pure helpers on their own: __pa_nodebug (both branches) and read_cr3_pa
    let np = 2_000_000u64; let mut hi = 0u64;
    for it in 0..np {
        if it % 512 == 0 { fresh(&mut r, &mut init, is_amd); unsafe { restore(init.as_ptr()); } }
        let x = match r.below(4) { 0 => r.next(), 1 => START.wrapping_add(r.below(1 << 30)), 2 => START.wrapping_sub(r.below(1 << 30)), _ => r.next() | (1 << 63) };
        let e = env(is_amd);
        let (c, rs) = unsafe { (c_pa_nodebug(x), e.pa_nodebug(x)) };
        let (c3, r3) = unsafe { (c_read_cr3_pa(), e.read_cr3_pa()) };
        if c != rs || c3 != r3 { println!("MISMATCH helpers x={x:#x}: pa C {c:#x} Rust {rs:#x}; cr3_pa C {c3:#x} Rust {r3:#x}"); std::process::exit(1); }
        if x >= START { hi += 1; }
    }
    println!("{n} cases C == Rust (return, {sz} bytes of state, every hook call): make_pgtable true {ok_true} / false {ok_false} ({l5_true} true with 5-level), exceptions: PF-handled {pf_true}, dispatch (PF/VC/VE/other) {dispatch:?}, {rr_reset} resets, {resets} cases wrote CR3; {np} pa_nodebug/read_cr3_pa pairs ({hi} on the x >= __START_KERNEL_map branch)");
}
