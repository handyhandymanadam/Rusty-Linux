// Userspace comparison: Rust gate_entry() (the stub's idt_64_rs.rs, included verbatim) vs the C above.
#![allow(dead_code, non_upper_case_globals)]
#[path = "../../port/tree/arch/x86/boot/compressed/idt_64_rs.rs"]
mod idt;
extern "C" { fn c_gate(a: u64, out: *mut [u64; 2]); }
fn main() {
    let mut n: u64 = 0;
    let mut chk = |a: u64| {
        let mut c = [0u64; 2];
        unsafe { c_gate(a, &mut c) };
        let r = idt::gate_entry(a);
        if c != [r.lo, r.hi] { println!("MISMATCH {a:#x}: C {c:x?} Rust {:x?}", [r.lo, r.hi]); std::process::exit(1); }
        n += 1;
    };
    for a in [0u64, 1, u64::MAX, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000, 0xffff_ffff_8000_0000] { chk(a); }
    for i in 0..64 { chk(1 << i); chk(!(1u64 << i)); chk((1u64 << i).wrapping_sub(1)); }
    for i in 0..(1u64 << 24) { chk(i); chk(i << 16); chk(i << 40); chk(!i); }   // dense low/middle/high slices
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for _ in 0..200_000_000u64 { x ^= x << 13; x ^= x >> 7; x ^= x << 17; chk(x); }
    println!("gate_entry: {n} addresses, C == Rust on every one");
}
