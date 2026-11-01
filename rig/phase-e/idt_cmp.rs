// Userspace differential: idt_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C cut out of the pristine idt.c (idt_ref.c).
// Random starting state (idt_table bytes, system_vectors, idt_descr), then the same operation on both sides; compared: the whole
// 4096-byte table, the bitmap, idt_descr, every lidt (size, address) in order, the BUG_ON count, and the early tables themselves.
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs)]
#[path = "IDTRS"]
mod h;
use h::{DescPtr, IdtData};
extern "C" {
    fn c_idt() -> *mut u8;
    fn c_descr() -> *mut u8;
    fn c_from_table(t: *const IdtData, n: i32, sys: i32);
    fn c_early_traps();
    fn c_early_pf();
    fn c_early_handler();
    fn c_vectors() -> *mut u8;
    fn c_bug() -> u32;
    fn c_lidt_reset();
    fn c_lidt_n() -> u32;
    fn c_lidt() -> *const u8;
    fn c_early_idts_len() -> usize;
    fn c_early_idts() -> *const IdtData;
    fn c_early_pf_idts() -> *const IdtData;
    fn c_gate_vec(addr: u64, seg: u32, bits: u16, hi: *mut u64) -> u64;
}
#[no_mangle]
pub extern "C" fn test_load_idt(d: *const DescPtr) {
    extern "C" { fn rust_lidt_record(size: u16, addr: u64); }
    unsafe { let s = core::ptr::addr_of!((*d).size).read_unaligned(); let a = core::ptr::addr_of!((*d).address).read_unaligned(); rust_lidt_record(s, a); }
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
}
fn rnd_addr(r: &mut Rng) -> u64 {
    match r.next() % 6 { 0 => r.next(), 1 => 0xffffffff80000000 | (r.next() & 0x3fffffff), 2 => r.next() & 0xffff, 3 => 0xffff_ffff_ffff_ffff, 4 => 1u64 << (r.next() % 64), _ => (r.next() & 0xffff_ffff) << 32 }
}
#[derive(PartialEq, Debug, Clone)]
struct State { idt: Vec<u8>, vec: Vec<u8>, descr: Vec<u8>, lidt: Vec<u8>, nl: u32, bug: u32 }
unsafe fn snap() -> State {
    State { idt: std::slice::from_raw_parts(c_idt(), 4096).to_vec(), vec: std::slice::from_raw_parts(c_vectors(), 32).to_vec(),
            descr: std::slice::from_raw_parts(c_descr(), 10).to_vec(), lidt: std::slice::from_raw_parts(c_lidt(), 16 * 16).to_vec(), nl: c_lidt_n(), bug: c_bug() }
}
unsafe fn load(init: &State) {
    std::ptr::copy_nonoverlapping(init.idt.as_ptr(), c_idt(), 4096);
    std::ptr::copy_nonoverlapping(init.vec.as_ptr(), c_vectors(), 32);
    std::ptr::copy_nonoverlapping(init.descr.as_ptr(), c_descr(), 10);
    c_lidt_reset(); RL.with(|l| l.borrow_mut().clear());
}
use std::cell::RefCell;
thread_local! { static RL: RefCell<Vec<(u16, u64)>> = RefCell::new(Vec::new()); }
#[no_mangle]
pub extern "C" fn rust_lidt_record(size: u16, addr: u64) { RL.with(|l| l.borrow_mut().push((size, addr))); }
fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let mut r = Rng(0x9e3779b97f4a7c15);
    let mut counts = [0u64; 5]; let mut sysn = 0u64; let mut gates = 0u64; let mut lidts = 0u64;
    unsafe {
        // the early tables themselves
        let el = c_early_idts_len(); let ct = std::slice::from_raw_parts(c_early_idts() as *const u8, el * 24);
        let rt = std::slice::from_raw_parts(h::early_tables().0.as_ptr() as *const u8, h::early_tables().0.len() * 24); assert_eq!(rt.len(), el * 24, "early_idts length");
        for k in 0..el { assert_eq!(&ct[k*24..k*24+4], &rt[k*24..k*24+4], "vector {k}"); assert_eq!(&ct[k*24+4..k*24+8], &rt[k*24+4..k*24+8], "segment {k}");
            assert_eq!(&ct[k*24+8..k*24+10], &rt[k*24+8..k*24+10], "bits {k}"); assert_eq!(&ct[k*24+16..k*24+24], &rt[k*24+16..k*24+24], "addr {k}"); }
        let cp = std::slice::from_raw_parts(c_early_pf_idts() as *const u8, 24); let rp = std::slice::from_raw_parts(h::early_tables().1.as_ptr() as *const u8, 24);
        for (a, b) in [(0usize, 4usize), (4, 8), (8, 10), (16, 24)] { assert_eq!(&cp[a..b], &rp[a..b], "early_pf_idts {a}"); }
        println!("early tables: early_idts {el} entries and early_pf_idts 1 entry equal (vector, segment, bits, addr)");
        // gate encoding on its own (the header inline's bitfield code vs the Rust arithmetic)
        for _ in 0..n {
            let a = rnd_addr(&mut r); let seg = r.next() as u32; let bits = r.next() as u16;
            let mut chi = 0u64; let clo = c_gate_vec(a, seg, bits, &mut chi);
            let d = IdtData { vector: 0, segment: seg, bits, addr: a as usize as *const _ };
            let (lo, hi) = h::gate_words(&d);
            if (lo, hi) != (clo, chi) { eprintln!("GATE MISMATCH addr={a:#x} seg={seg:#x} bits={bits:#x}: C {clo:#x}/{chi:#x} Rust {lo:#x}/{hi:#x}"); std::process::exit(1); }
            gates += 1;
        }
        // operations on the state
        for i in 0..n {
            let mut init = State { idt: vec![0; 4096], vec: vec![0; 32], descr: vec![0; 10], lidt: vec![], nl: 0, bug: 0 };
            for b in init.idt.iter_mut() { *b = r.next() as u8; }
            for b in init.vec.iter_mut() { *b = r.next() as u8; }
            for b in init.descr.iter_mut() { *b = r.next() as u8; }
            let op = i % 4; let mut tab: Vec<IdtData> = vec![]; let mut sys = false; let mut nt = 0usize;
            if op == 0 {
                nt = (r.next() % 9) as usize; sys = r.next() & 1 == 1;
                for _ in 0..nt {
                    let vector = match r.next() % 3 { 0 => (r.next() % 256) as u32, 1 => (r.next() % 32) as u32, _ => [0u32, 255, 63, 64, 127, 128, 191, 192][(r.next() % 8) as usize] };
                    tab.push(IdtData { vector, segment: r.next() as u32, bits: r.next() as u16, addr: rnd_addr(&mut r) as usize as *const _ });
                }
            }
            load(&init);
            match op { 0 => c_from_table(tab.as_ptr(), nt as i32, sys as i32), 1 => c_early_traps(), 2 => c_early_pf(), _ => c_early_handler() }
            let cs = snap(); let cl: Vec<(u16, u64)> = (0..cs.nl.min(16) as usize).map(|k| { let p = c_lidt().add(k * 16); (u16::from_le_bytes([*p, *p.add(1)]), u64::from_le_bytes(std::slice::from_raw_parts(p.add(8), 8).try_into().unwrap())) }).collect();
            load(&init);
            match op {
                0 => h::setup_from_table(c_idt(), tab.as_ptr(), nt as i32, sys),
                1 => h::early_traps(c_idt(), c_descr() as *const DescPtr),
                2 => h::early_pf(c_idt()),
                _ => h::early_handler(c_idt(), c_descr() as *const DescPtr),
            }
            let mut rs = snap(); let rl: Vec<(u16, u64)> = RL.with(|l| l.borrow().clone());
            rs.lidt = cs.lidt.clone(); rs.nl = cs.nl; // C's record is compared through `cl` vs `rl` below
            if cs.idt != rs.idt || cs.vec != rs.vec || cs.descr != rs.descr || cs.bug != rs.bug || cl != rl {
                eprintln!("MISMATCH op={op} nt={nt} sys={sys}\n  lidt C {cl:?} Rust {rl:?}");
                for k in 0..4096 { if cs.idt[k] != rs.idt[k] { eprintln!("  idt byte {k}: C {:#x} Rust {:#x}", cs.idt[k], rs.idt[k]); break; } }
                for k in 0..32 { if cs.vec[k] != rs.vec[k] { eprintln!("  vectors byte {k}: C {:#x} Rust {:#x}", cs.vec[k], rs.vec[k]); } }
                std::process::exit(1);
            }
            counts[op as usize] += 1; if op == 0 && sys { sysn += 1 } lidts += rl.len() as u64;
            if op == 0 { }
        }
    }
    println!("idt_cmp: {} gate encodings and {} operations equal C == Rust (4096-byte table, 256-bit bitmap, idt_descr, lidt calls, BUG_ON count); from_table {} (sys=true {}), early_traps {}, early_pf {}, early_handler {}; lidt calls seen {}",
             gates, counts.iter().sum::<u64>(), counts[0], sysn, counts[1], counts[2], counts[3], lidts);
}
