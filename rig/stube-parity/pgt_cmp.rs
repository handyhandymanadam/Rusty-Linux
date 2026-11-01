// Userspace comparison: pgtable_64_rs.rs (included verbatim) vs the kernel's C (pgt_ref.c, extracted
// by gen-pgt-ref.sh): trampoline_placement() and sanitize_boot_params() on millions of inputs.
#![allow(dead_code, non_upper_case_globals)]
#[path = "../../port/tree/arch/x86/boot/compressed/pgtable_64_rs.rs"]
mod pgt;
use pgt::E820Entry;
extern "C" {
    fn c_place(efi: i32, ebda: u16, bios: u16, tab: *const E820Entry, n: i32) -> u64;
    fn c_sanitize(bp: *mut u8);
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
    fn below(&mut self, n: u64) -> u64 { self.next() % n }
}
/// addresses biased to the interesting places: page edges, the 640K limit, 0, wraparound
fn addr(r: &mut Rng) -> u64 {
    const K: [u64; 14] = [0, 0x1000, 0x2000, 0x20000, 0x9f000, 0x9e000, 0x9fc00, 0x100000, 0x7fff_f000, 0x1_0000_0000,
        u64::MAX - 0x1fff, u64::MAX - 0xfff, u64::MAX, 0x8000_0000_0000_0000];
    match r.below(4) {
        0 => K[r.below(14) as usize].wrapping_add(r.below(0x3000)).wrapping_sub(0x1000),
        1 => (r.below(0x400) << 12) + r.below(2) * r.below(0x1000),
        2 => r.below(0x10_0000),
        _ => r.next(),
    }
}
fn main() {
    let mut r = Rng(0x9E3779B97F4A7C15);
    let (mut np, mut top) = (0u64, 0u64);
    for _ in 0..30_000_000u64 {
        let efi = r.below(3) as i32;
        let (ebda, bios) = match r.below(3) {
            0 => (r.below(0x10000) as u16, r.below(0x10000) as u16),
            1 => (0x9fc0 >> 0, 639),            // typical BIOS values
            _ => (r.below(0xa000) as u16, (0x80 + r.below(0x40)) as u16),
        };
        let n = match r.below(4) { 0 => 0, 1 => 1 + r.below(3), 2 => 1 + r.below(8), _ => 1 + r.below(128) } as usize;
        let tab: Vec<E820Entry> = (0..n).map(|_| {
            let a = addr(&mut r);
            let s = if r.below(3) == 0 { addr(&mut r) } else { r.below(0x20_0000) << 4 };
            E820Entry { addr: a, size: s, typ: [1, 1, 1, 2, 3, 4, 7, 12, 0, 5][r.below(10) as usize] }
        }).collect();
        let c = unsafe { c_place(efi, ebda, bios, tab.as_ptr(), n as i32) };
        let rs = pgt::trampoline_placement(efi != 0, ebda, bios, &tab);
        if c != rs { println!("PLACEMENT MISMATCH efi={efi} ebda={ebda:#x} bios={bios:#x} n={n}: C {c:#x} Rust {rs:#x}\n{:x?}",
            tab.iter().map(|e| (e.addr, e.size, e.typ)).collect::<Vec<_>>()); std::process::exit(1); }
        np += 1;
        if rs == 0x9f000 - 8192 { top += 1; }
    }
    println!("trampoline_placement: {np} random cases, C == Rust on all ({top} placed at the 0x9d000 default, {} placed lower by BIOS words / e820)", np - top);

    let mut ns = 0u64;
    for i in 0..2_000_000u64 {
        let mut a = vec![0u8; 4096];
        for b in a.iter_mut() { *b = r.next() as u8; }
        match i % 4 { 0 => a[0x1ef] = 0, 1 => a[0x1ef] = 0xff, 2 => {}, _ => { a[0x1ef] = 1 } }
        let mut b = a.clone();
        let mut scratch = vec![0xAAu8; 4096];
        unsafe { c_sanitize(a.as_mut_ptr()); pgt::sanitize_boot_params(b.as_mut_ptr(), scratch.as_mut_ptr()); }
        if a != b { let d = (0..4096).find(|&k| a[k] != b[k]).unwrap(); println!("SANITIZE MISMATCH at byte {d:#x}"); std::process::exit(1); }
        ns += 1;
    }
    println!("sanitize_boot_params: {ns} random 4 KiB buffers (1/4 sentinel=0), C == Rust on all");
}
