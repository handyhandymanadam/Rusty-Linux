// SPDX-License-Identifier: GPL-2.0
//! Rust half of the offsetof() cross-check -- see check_offsets.c and
//! check_offsets.sh. `include!`s a stripped copy of the real port file
//! (check_offsets.sh makes the copy; its `//!` module docs and `#![allow]`
//! line are illegal pasted at a non-crate-root `include!` site).

include!(env!("ZSTD_DECOMPRESS_BLOCK_RS_STRIPPED"));

macro_rules! off {
    ($f:ident) => {
        println!("{:<24} {}", stringify!($f), core::mem::offset_of!(ZstdDCtx, $f));
    };
}

fn main() {
    println!("sizeof(ZstdDCtx) = {}", core::mem::size_of::<ZstdDCtx>());
    println!("sizeof(EntropyDTables) = {}", core::mem::size_of::<EntropyDTables>());
    println!("sizeof(SeqSymbol) = {}", core::mem::size_of::<SeqSymbol>());
    off!(LLTptr); off!(MLTptr); off!(OFTptr); off!(HUFptr); off!(entropy); off!(workspace);
    off!(previousDstEnd); off!(prefixStart); off!(virtualStart); off!(dictEnd);
    off!(expected); off!(fParams); off!(processedCSize); off!(decodedSize);
    off!(bType); off!(stage); off!(litEntropy); off!(fseEntropy); off!(xxhState);
    off!(headerSize); off!(format); off!(forceIgnoreChecksum); off!(validateChecksum);
    off!(litPtr); off!(customMem); off!(litSize); off!(rleSize); off!(staticSize);
    off!(isFrameDecompression);
    off!(bmi2);
    off!(ddictLocal); off!(ddict); off!(dictID); off!(ddictIsCold); off!(dictUses);
    off!(ddictSet); off!(refMultipleDDicts); off!(disableHufAsm); off!(maxBlockSizeParam);
    off!(streamStage); off!(inBuff); off!(inBuffSize); off!(inPos); off!(maxWindowSize);
    off!(outBuff); off!(outBuffSize); off!(outStart); off!(outEnd); off!(lhSize);
    off!(hostageByte); off!(noForwardProgress); off!(outBufferMode); off!(expectedOutBuffer);
    off!(litBuffer); off!(litBufferEnd); off!(litBufferLocation); off!(litExtraBuffer);
    off!(headerBuffer); off!(oversizedDuration);
}
