#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the pure checks of the PRISTINE efi.c (C side: pmbr_part_valid, is_pmbr_valid, the header checks of is_gpt_valid wrapped in a function of their own, is_pte_valid,
compare_gpts, utf16_le_to_7bit), or the same names as the glue's thunks plus its wrappers (Rust side), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
glue = "RUST-WRAPPERS BEGIN" in s
def fn(sig, end="\n}\n"):
    a = s.index(sig); return s[a:s.index(end, a) + len(end)]
if glue:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")] + fn("static int is_pmbr_valid(") + fn("static inline int\nis_pte_valid(") + fn("static void\ncompare_gpts(") + fn("static void utf16_le_to_7bit(")
    a = s.index("\tlastlba = last_lba(state->disk);\n\tif (rust_efi_gpt_header_check("); b = s.index("\tpt_size = (u64)le32_to_cpu((*gpt)->num_partition_entries) *")
    seg = s[a:b]
else:
    body = fn("static inline int pmbr_part_valid(") + fn("static int is_pmbr_valid(") + fn("static inline int\nis_pte_valid(") + fn("static void\ncompare_gpts(") + fn("static void utf16_le_to_7bit(")
    a = s.index("\tif (le64_to_cpu((*gpt)->signature) != GPT_HEADER_SIGNATURE) {"); b = s.index("\tpt_size = (u64)le32_to_cpu((*gpt)->num_partition_entries) *")
    seg = "\tlastlba = last_lba(state->disk);\n" + s[a:b] if False else s[a:b]
    # the C original computes lastlba in the middle of the segment; keep the text as is
fnc = "static int header_check(gpt_header *gpt_, u64 lba, u64 lastlba_, unsigned int ssz_)\n{\n\tu32 crc, origcrc; u64 lastlba = lastlba_; gpt_header **gpt = &gpt_;\n\tstruct parsed_partitions *state = &g_state;\n\tg_ssz = ssz_; g_lastlba = lastlba_;\n"
if glue:
    fnc += "\tif (rust_efi_gpt_header_check((u8 *)*gpt, lba, lastlba, ssz_)) return 1;\n\treturn 0;\n}\n"
else:
    fnc += seg.replace("\tlastlba = last_lba(state->disk);\n", "\tlastlba = last_lba(state->disk);\n") + "\treturn 0;\nfail:\n\treturn 1;\n}\n"
open(sys.argv[2], "w").write('#include "refshim.h"\n' + body + "\n" + fnc)
