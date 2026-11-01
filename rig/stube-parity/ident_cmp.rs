// Userspace comparison: ident_map_64_rs.rs (included verbatim) vs the original C (ident_map_64.c with
// the shared ident_map.c, compiled for the host by ident-ref.sh). Both build page tables in the same
// arena at the same addresses (entries hold absolute addresses), then the arenas, the mapping_info
// structs and return codes are compared. 4-level and 5-level modes, gbpages on/off, tiny arenas
// (out-of-memory paths), appending to existing tables, and the 2M->4K split of set_page_non_present().
#![allow(dead_code, non_upper_case_globals, static_mut_refs)]
#[path = "../../port/tree/arch/x86/boot/compressed/ident_map_64_rs.rs"]
mod ident;
use ident::MappingInfo;
use std::ffi::c_void;

#[repr(C)]
struct Arena { base: *mut u8, pages: u64, used: u64 }
extern "C" {
    fn mmap(a: *mut c_void, l: usize, p: i32, f: i32, fd: i32, o: i64) -> *mut c_void;
    fn arena_alloc(ctx: *mut c_void) -> *mut c_void;
    fn guarded_add(f: unsafe extern "C" fn(u64, u64), a: u64, b: u64) -> i32;
    fn guarded_init(f: unsafe extern "C" fn(*mut u8), a: *mut u8) -> i32;
    fn guarded_set(f: unsafe extern "C" fn(u64) -> i32, a: u64, out: *mut i32) -> i32;
    static mut __pgtable_l5_enabled: u32;
    static mut pgdir_shift: u32;
    static mut ptrs_per_p4d: u32;
    fn c_kernel_ident_mapping_init(info: *mut MappingInfo, pgd: *mut u64, s: u64, e: u64) -> i32;
    fn c_kernel_add_identity_map(s: u64, e: u64);
    fn c_set_page_non_present(a: u64) -> i32;
    static mut c_mapping_info: MappingInfo;
    static mut c_top_level_pgt: u64;
    static mut c___default_kernel_pte_mask: u64;
    fn c_initialize_identity_maps(rmode: *mut u8);
    static mut c_pgt_data: ident::AllocPgtData;
    static mut test_cr3: u64;
    static mut test_cmdline: u64;
    static mut _pgtable: [u8; 32 * 4096];
    static mut boot_params_ptr: *mut u8;
    static _head: u8;
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}
const ARENA_PAGES: usize = 64;
fn mk_info(r: &mut Rng, ar: *mut Arena) -> MappingInfo {
    MappingInfo {
        alloc_pgt_page: Some(arena_alloc), free_pgt_page: None, context: ar as *mut c_void,
        page_flag: [0x1e3u64, 0x83, 0x1e3 | (1 << 63), 0xe3][r.below(4) as usize],
        offset: [0u64, 0, 0, 0x20_0000, 0x4000_0000, 0x1000][r.below(6) as usize],
        direct_gbpages: r.below(2) == 0,
        kernpg_flag: [0u64, 0x63, 0x67, 0x63 | (1 << 62)][r.below(4) as usize],
    }
}
fn range(r: &mut Rng, l5: bool) -> (u64, u64) {
    let top = if l5 { 57 } else { 48 };
    let base = match r.below(6) {
        0 => r.below(1 << 32),
        1 => r.below(8) << 30,
        2 => (r.below(1 << (top - 39)) << 39).wrapping_sub(r.below(1 << 22)),
        3 => (r.below(4) << (top - 2)).wrapping_sub(r.below(1 << 31)),
        4 => r.next() >> (64 - top),
        _ => (r.below(64) << 21) + r.below(1 << 21),
    };
    let len = match r.below(5) { 0 => r.below(1 << 12), 1 => r.below(1 << 22), 2 => r.below(1 << 31), 3 => r.below(1 << 36), _ => r.below(1 << 41) };
    // Not within ~2 GiB of 2^64: with an unrounded end there, ident_pmd_init()'s `addr += PMD_SIZE` wraps to 0
    // and loops ~2^43 times in the C (and the Rust copy). The stub cannot get there: kernel_add_identity_map()
    // rounds `end` up to 2 MiB first, which wraps to 0 and returns. (Kept out of the random cases, noted in the log.)
    const LIM: u64 = 0xffff_ffff_7fc0_0000; // also leaves room for info.offset (<= 1 GiB)
    let base = base.min(LIM);
    (base, base.saturating_add(len).min(LIM))
}
fn snap(a: *mut u8, ar: &Arena, info: &MappingInfo) -> (Vec<u8>, u64) {
    (unsafe { std::slice::from_raw_parts(a, (ar.pages as usize + 1) * 4096).to_vec() }, ar.used + info.kernpg_flag.wrapping_mul(0x9E37) )
}
fn main() {
    let mut r = Rng(0x2545F4914F6CDD1D);
    let layout = std::alloc::Layout::from_size_align(ARENA_PAGES * 4096, 4096).unwrap();
    let base = unsafe { std::alloc::alloc_zeroed(layout) };
    let mut ar = Arena { base, pages: 0, used: 0 };
    let (mut n_init, mut n_oom, mut n_add, mut n_err) = (0u64, 0u64, 0u64, 0u64);

    // ---- A: kernel_ident_mapping_init() with random mapping_info ----
    for trial in 0..150_000u64 {
        let l5 = r.below(2) == 0;
        unsafe { __pgtable_l5_enabled = l5 as u32; pgdir_shift = if l5 { 48 } else { 39 }; ptrs_per_p4d = if l5 { 512 } else { 1 };
                 c___default_kernel_pte_mask = [!0u64, !0, !(1 << 62), !(1 << 63)][r.below(4) as usize]; ident::__default_kernel_pte_mask = c___default_kernel_pte_mask; }
        let tiny = r.below(5) == 0;
        let npages = if tiny { 2 + r.below(6) } else { 8 + r.below(ARENA_PAGES as u64 - 8) };
        let info0 = mk_info(&mut r, &mut ar);
        let nrange = 1 + r.below(6);
        let ranges: Vec<_> = (0..nrange).map(|_| range(&mut r, l5)).collect();
        let mut res = Vec::new();
        for who in 0..2 {
            unsafe { std::ptr::write_bytes(base, 0, (npages as usize + 1) * 4096); }
            ar.pages = npages; ar.used = 0;
            let pgd = unsafe { arena_alloc(&mut ar as *mut _ as *mut c_void) } as *mut u64;
            let mut info = MappingInfo { ..info0 };
            let mut rcs = Vec::new();
            for &(s, e) in &ranges {
                let rc = unsafe { if who == 0 { c_kernel_ident_mapping_init(&mut info, pgd, s, e) } else { ident::kernel_ident_mapping_init(&mut info, pgd, s, e) } };
                rcs.push(rc);
            }
            res.push((snap(base, &ar, &info), rcs, info.kernpg_flag));
        }
        if res[0] != res[1] {
            println!("MISMATCH in kernel_ident_mapping_init, trial {trial} l5={l5} tiny={tiny} npages={npages} gb={} off={:#x} pf={:#x} kpf={:#x} ranges {:x?}\n  rc C {:?} Rust {:?}",
                info0.direct_gbpages, info0.offset, info0.page_flag, info0.kernpg_flag, ranges, res[0].1, res[1].1);
            let d = (0..res[0].0.0.len()).find(|&k| res[0].0.0[k] != res[1].0.0[k]); println!("  first differing arena byte: {d:x?}");
            std::process::exit(1);
        }
        n_init += 1; if res[0].1.iter().any(|&c| c != 0) { n_oom += 1; }
    }
    println!("kernel_ident_mapping_init: {n_init} cases (4- and 5-level, {n_oom} with -ENOMEM), arenas+mapping_info+rc identical C vs Rust");

    // ---- B: kernel_add_identity_map() + set_page_non_present() on the file-local state ----
    // a host region R (6 MiB at 1 GiB, inside the first top-level entry: set_clr_page_flags() walks
    // from entry 0 of the top-level table for ANY address -- p4d_offset(pgdp, address) is the pgd itself
    // in 4-level mode -- so only addresses below 512 GiB are valid input) so the C's "read the page to
    // fault it in" step can run on real memory
    let rbase = unsafe { mmap(0x4000_0000usize as *mut c_void, 6 << 20, 3, 0x22 | 0x100000, -1, 0) } as u64;   // MAP_FIXED_NOREPLACE
    assert_eq!(rbase, 0x4000_0000, "could not map the test region at 1 GiB");
    for trial in 0..100_000u64 {
        let l5 = r.below(2) == 0;
        unsafe { __pgtable_l5_enabled = l5 as u32; pgdir_shift = if l5 { 48 } else { 39 }; ptrs_per_p4d = if l5 { 512 } else { 1 };
                 c___default_kernel_pte_mask = !0; ident::__default_kernel_pte_mask = !0; }
        let npages = 6 + r.below(ARENA_PAGES as u64 - 6);   // >= 6: enough for the initial map of R in both modes
        let info0 = mk_info(&mut r, &mut ar);
        let nops = 1 + r.below(8);
        // op: (kind, a, b)
        let ops: Vec<(u8, u64, u64)> = (0..nops).map(|_| match r.below(3) {
            0 => { let (s, e) = range(&mut r, l5); (0, s, e) }
            1 => (0, rbase + r.below(6 << 20), rbase + r.below(8 << 20)),   // inside / around R (also start>=end)
            _ => (1, rbase + r.below(6 << 20), 0),                          // set_page_non_present
        }).collect();
        let mut res = Vec::new();
        for who in 0..2 {
            unsafe { std::ptr::write_bytes(base, 0, (npages as usize + 1) * 4096); }
            ar.pages = npages; ar.used = 0;
            let pgd = unsafe { arena_alloc(&mut ar as *mut _ as *mut c_void) } as u64;
            let mut rcs = Vec::new();
            unsafe {
                let mi = MappingInfo { direct_gbpages: false, offset: 0, page_flag: 0x1e3, kernpg_flag: 0x63, ..info0 };
                if who == 0 { c_mapping_info = mi; c_top_level_pgt = pgd; } else { ident::mapping_info = mi; ident::top_level_pgt = pgd; }
                // R is mapped first (as the real stub maps what it touches) so the read in set_clr_page_flags is host-valid
                let e = if who == 0 { guarded_add(c_kernel_add_identity_map, rbase, rbase + (6 << 20)) } else { guarded_add(ident::kernel_add_identity_map, rbase, rbase + (6 << 20)) };
                assert_eq!(e, 0, "initial mapping of R failed (arena too small)");
                for &(k, a, b) in &ops {
                    if k == 0 { rcs.push(if who == 0 { guarded_add(c_kernel_add_identity_map, a, b) } else { guarded_add(ident::kernel_add_identity_map, a, b) }) }
                    else { let mut o = 0i32; let e = if who == 0 { guarded_set(c_set_page_non_present, a, &mut o) } else { guarded_set(ident::set_page_non_present, a, &mut o) }; rcs.push(if e != 0 { 1000 } else { o }) }
                }
            }
            res.push((snap(base, &ar, unsafe { if who == 0 { &c_mapping_info } else { &ident::mapping_info } }), rcs));
        }
        if res[0] != res[1] {
            println!("MISMATCH in kernel_add_identity_map/set_page_non_present, trial {trial} l5={l5} npages={npages} ops {:x?}\n  rc C {:?} Rust {:?}", ops, res[0].1, res[1].1);
            let d = (0..res[0].0.0.len()).find(|&k| res[0].0.0[k] != res[1].0.0[k]); println!("  first differing arena byte: {d:x?}");
            std::process::exit(1);
        }
        n_add += 1; if res[0].1.iter().any(|&c| c != 0) { n_err += 1; }
    }
    println!("kernel_add_identity_map + set_page_non_present: {n_add} sequences ({n_err} reached error() or -ENOMEM), arenas+state+outcomes identical C vs Rust");

    // ---- C: initialize_identity_maps() end to end (CR3 read/write seams in both): startup_32 layout vs the
    //         "allocate a new top level" branch, 4/5-level, 0..3 setup_data nodes, random command-line spot ----
    let (mut n_init2, mut n_b1, mut n_err2) = (0u64, 0u64, 0u64);
    let page = |n: usize| -> *mut u8 { unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::from_size_align(n * 4096, 4096).unwrap()) } };
    let top = page(1) as *mut u64;
    // 16 KiB of real memory straddling the 2 MiB boundary at 2 GiB, so a setup_data node / command line can end
    // exactly at, one byte before or one byte after a 2 MiB boundary (where an off-by-16 or off-by-1 shows)
    let edge = unsafe { mmap(0x7fff_e000usize as *mut c_void, 0x4000, 3, 0x22 | 0x100000, -1, 0) } as u64;
    assert_eq!(edge, 0x7fff_e000, "could not map the edge region");
    for trial in 0..60_000u64 {
        let l5 = r.below(2) == 0;
        let branch1 = r.below(2) == 0;
        let nsd = r.below(4) as usize;
        let bp = page(1);
        let cmdline = if r.below(3) == 0 { (0x8000_0000u64 - 2048).wrapping_add((r.below(5) as u64).wrapping_sub(2)) } else { r.below(1 << 40) & !0xf };
        let mut sd_prev = 0u64;
        for k in 0..nsd {
            let len = [0u32, 1, 100, 5000, 4096, 1000][r.below(6) as usize];
            let n = if k == 0 && r.below(2) == 0 {
                (0x8000_0000u64 - 16 - len as u64).wrapping_add((r.below(5) as u64).wrapping_sub(2)) as *mut u8   // ends within 2 bytes of the boundary
            } else { unsafe { page(2).add(r.below(4096 - 16) as usize) } };
            unsafe {
                (n as *mut u64).write_unaligned(sd_prev);                                   // next
                (n.add(12) as *mut u32).write_unaligned(len);                               // len
            }
            sd_prev = n as u64;
        }
        unsafe { (bp.add(0x250) as *mut u64).write_unaligned(sd_prev); }                    // hdr.setup_data
        let mut res = Vec::new();
        for who in 0..2 {
            unsafe {
                __pgtable_l5_enabled = l5 as u32; pgdir_shift = if l5 { 48 } else { 39 }; ptrs_per_p4d = if l5 { 512 } else { 1 };
                c___default_kernel_pte_mask = !0; ident::__default_kernel_pte_mask = !0;
                std::ptr::write_bytes(_pgtable.as_mut_ptr(), 0, 32 * 4096);
                // startup_32-style tables in the first 6 pages: top, pud, 4 pmd pages of 2 MiB leaves (4 GiB)
                let pg = _pgtable.as_mut_ptr() as *mut u64; let base = pg as u64;
                *pg = (base + 4096) | 0x63;
                for i in 0..4 { *pg.add(512 + i) = (base + 4096 * (2 + i as u64)) | 0x63; }
                for i in 0..2048u64 { *pg.add(1024 + i as usize) = (i << 21) | 0x83; }
                std::ptr::write_bytes(top as *mut u8, 0, 4096);
                if branch1 { if l5 { *top = base | 0x63; test_cr3 = top as u64; } else { test_cr3 = base; } }
                else { *top = 0x1000 | 0x63; test_cr3 = top as u64; }
                test_cmdline = cmdline;
                boot_params_ptr = std::ptr::null_mut();
                if who == 0 { c_pgt_data = ident::AllocPgtData { pgt_buf: std::ptr::null_mut(), pgt_buf_size: 7, pgt_buf_offset: 7 }; }
                else { ident::pgt_data = ident::AllocPgtData { pgt_buf: std::ptr::null_mut(), pgt_buf_size: 7, pgt_buf_offset: 7 }; }
                let e = if who == 0 { guarded_init(c_initialize_identity_maps, bp) } else { guarded_init(ident::initialize_identity_maps, bp) };
                let (pd, tl, mi) = if who == 0 { (&c_pgt_data, c_top_level_pgt, &c_mapping_info) } else { (&ident::pgt_data, ident::top_level_pgt, &ident::mapping_info) };
                let scal = vec![e as u64, pd.pgt_buf as u64, pd.pgt_buf_size, pd.pgt_buf_offset, tl, mi.page_flag, mi.kernpg_flag, mi.offset,
                                mi.direct_gbpages as u64, mi.alloc_pgt_page.is_some() as u64, boot_params_ptr as u64];
                res.push((scal, std::slice::from_raw_parts(_pgtable.as_ptr(), 32 * 4096).to_vec(), std::slice::from_raw_parts(top as *const u8, 4096).to_vec()));
            }
        }
        if res[0] != res[1] {
            println!("MISMATCH in initialize_identity_maps, trial {trial} l5={l5} branch1={branch1} nsd={nsd}\n  C: err={} buf={:#x} size={:#x} off={:#x} top={:#x} | Rust: err={} buf={:#x} size={:#x} off={:#x} top={:#x}",
                res[0].0[0], res[0].0[1], res[0].0[2], res[0].0[3], res[0].0[4], res[1].0[0], res[1].0[1], res[1].0[2], res[1].0[3], res[1].0[4]);
            let d = (0..32 * 4096).find(|&k| res[0].1[k] != res[1].1[k]); println!("  first differing _pgtable byte: {d:x?}");
            std::process::exit(1);
        }
        n_init2 += 1; if branch1 { n_b1 += 1; } if res[0].0[0] != 0 { n_err2 += 1; }
    }
    println!("initialize_identity_maps: {n_init2} runs ({n_b1} via the startup_32 branch, {} via the allocate-new-top branch; {n_err2} reached error()), page tables + state identical C vs Rust", n_init2 - n_b1);
}
