// SPDX-License-Identifier: GPL-2.0
//! Rust-side half of the font_8x16 byte-exact check -- see
//! layout_probe.c's own doc comment for the full picture. Built with
//! `--cfg fonts_test_probe`, which exposes font_8x16_rs.rs's two
//! test-only accessors (its fields are otherwise private).

#[path = "../../tree/lib/fonts/font_8x16_rs.rs"]
mod font_8x16_rs;

fn main() {
    let (idx, name, width, height, charcount, pref) = font_8x16_rs::font_vga_8x16_fields();
    let data = font_8x16_rs::fontdata_8x16_bytes();

    println!("idx={idx}");
    println!("name={name}");
    println!("width={width}");
    println!("height={height}");
    println!("charcount={charcount}");
    println!("pref={pref}");

    // REFCOUNT/FNTSIZE/FNTCHARCNT/FNTSUM: read the 16-byte extra[]
    // header immediately before `data` (font_8x16_rs.rs's own module
    // doc), matching the C's `((int *)(fd->data))[-N]` macros exactly.
    let base = data.as_ptr() as *const i32;
    let refcount = unsafe { *base.offset(-1) };
    let fntsize = unsafe { *base.offset(-2) };
    let fntcharcnt = unsafe { *base.offset(-3) };
    let fntsum = unsafe { *base.offset(-4) };
    println!("REFCOUNT={refcount}");
    println!("FNTSIZE={fntsize}");
    println!("FNTCHARCNT={fntcharcnt}");
    println!("FNTSUM={fntsum}");

    for (i, b) in data.iter().enumerate() {
        println!("data[{i}]={b:02x}");
    }
}
