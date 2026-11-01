// Userspace comparison: Rust interrupt_gate() (gdt_idt_rs.rs included verbatim) vs the kernel's C
// init_idt_data()/idt_init_desc()/native_write_idt_entry() (rig/phase-e/gdt_idt_ref.c).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs)]
#[path = "../../port/tree/arch/x86/boot/startup/gdt_idt_rs.rs"]
mod gdt;
extern "C" { fn c_vc_table(h: u64, out: *mut [u64; 2], others_zero: *mut i32); }
fn main() {
    let mut n: u64 = 0;
    let mut chk = |a: u64| {
        let mut c = [0u64; 2]; let mut z = 0i32;
        unsafe { c_vc_table(a, &mut c, &mut z) };
        let r = gdt::interrupt_gate(a);
        if z != 1 || c != [r.lo, r.hi] { println!("MISMATCH {a:#x}: C {c:x?} Rust {:x?}", [r.lo, r.hi]); std::process::exit(1); }
        n += 1;
    };
    for a in [0u64, 1, u64::MAX, 0xffff, 0x10000, 0xffff_ffff, 0x1_0000_0000, 0xffff_ffff_8000_0000] { chk(a); }
    for i in 0..64 { chk(1 << i); chk(!(1u64 << i)); chk((1u64 << i).wrapping_sub(1)); }
    for i in 0..(1u64 << 24) { chk(i); chk(i << 16); chk(i << 40); chk(!i); }
    let mut x: u64 = 0x9E3779B97F4A7C15;
    for _ in 0..(std::env::var("N").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000_000u64)) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; chk(x); }
    println!("interrupt_gate: {n} addresses, C == Rust on every one (also: no other table byte touched in C)");
}
