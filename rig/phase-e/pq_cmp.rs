// Userspace differential: platform_quirks_rs.rs (included verbatim, --cfg userspace_test) vs the REAL C of
// platform-quirks.c (pq_ref.c) on a struct x86_platform_ops with random initial bytes, for every hardware_subarch
// 0..=64 and random/edge 32-bit values, with set_legacy_features NULL and non-NULL (a callback that reads and
// mutates the legacy fields, so it is sensitive to ordering and to what was written before it).
#![allow(dead_code, non_upper_case_globals, unexpected_cfgs)]
#[path = "PQRS"]
mod h;
extern "C" {
    fn xp_ptr() -> *mut u8;
    fn xp_size() -> usize;
    fn set_subarch(v: u32);
    fn cb_ptr() -> *const u8;
    fn cb_calls() -> u32;
    fn cb_reset();
    fn c_quirks();
    fn c_pnp_disabled() -> i32;
}
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 { let mut x = self.0; x ^= x << 13; x ^= x >> 7; x ^= x << 17; self.0 = x; x }
}
fn main() {
    let n: u64 = std::env::var("N").ok().and_then(|s| s.parse().ok()).unwrap_or(200_000);
    let mut r = Rng(0x9e3779b97f4a7c15);
    let (xp, sz) = unsafe { (xp_ptr(), xp_size()) };
    let mut tot = 0u64; let mut cbn = 0u64; let mut pnp = 0u64; let mut per = [0u64; 6];
    let mut cases: Vec<u32> = (0..=64).collect();
    cases.extend([0x8000_0000, 0xffff_ffff, 0x1_0000 - 1, 0x1_0000, 0x7fff_ffff, 0x100, 3 | 0x100, 4 | 0x8000_0000]);
    for i in 0..n {
        let sub = if (i as usize) < cases.len() { cases[i as usize] } else { match r.next() % 3 { 0 => (r.next() % 8) as u32, 1 => r.next() as u32, _ => (r.next() as u32) & 0xf } };
        let with_cb = (r.next() & 1) == 1;
        let mut init = vec![0u8; sz];
        for b in init.iter_mut() { *b = r.next() as u8; }
        // the callback pointer slot (offset 112)
        let cbp: usize = if with_cb { unsafe { cb_ptr() as usize } } else { 0 };
        init[112..120].copy_from_slice(&cbp.to_le_bytes());
        unsafe {
            set_subarch(sub);
            std::ptr::copy_nonoverlapping(init.as_ptr(), xp, sz);
            cb_reset(); c_quirks();
            let c_state = std::slice::from_raw_parts(xp, sz).to_vec(); let c_calls = cb_calls(); let c_pnp = c_pnp_disabled();
            std::ptr::copy_nonoverlapping(init.as_ptr(), xp, sz);
            cb_reset();
            h::apply(xp, sub);
            let r_state = std::slice::from_raw_parts(xp, sz).to_vec(); let r_calls = cb_calls();
            let r_pnp = h::pnpbios_disabled((xp.add(88 + 20) as *const i32).read()) as i32;
            // pnpbios_disabled on the post-state of the C run too
            std::ptr::copy_nonoverlapping(c_state.as_ptr(), xp, sz);
            let c_pnp_post = c_pnp_disabled();
            let r_pnp_post = h::pnpbios_disabled((xp.add(88 + 20) as *const i32).read()) as i32;
            if c_state != r_state || c_calls != r_calls || c_pnp != r_pnp || c_pnp_post != r_pnp_post {
                eprintln!("MISMATCH sub={sub:#x} cb={with_cb} calls {c_calls}/{r_calls} pnp {c_pnp}/{r_pnp} post {c_pnp_post}/{r_pnp_post}");
                for k in 0..sz { if c_state[k] != r_state[k] { eprintln!("  byte {k}: C {:#x} Rust {:#x}", c_state[k], r_state[k]); } }
                std::process::exit(1);
            }
            tot += 1; if with_cb { cbn += 1 } if c_pnp != 0 { pnp += 1 }
            per[match sub { 0 => 0, 2 => 1, 3 => 2, 4 => 3, 1 => 4, _ => 5 }] += 1;
        }
    }
    println!("pq_cmp: {tot} cases equal C == Rust (struct bytes {sz} B, callback calls, pnpbios_disabled); with callback {cbn}; pnpbios_disabled true {pnp}; by subarch PC/XEN/MID/CE4100/LGUEST/other = {:?}", per);
}
