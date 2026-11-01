#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- bitset_glue.c = upstream net/ethtool/bitset.c without the u32-bitmap helpers and ethnl_bitset32_size (they are in bitset_rs.rs)."""
import sys
s = open(sys.argv[1]).read()
def cut(a_sig, b_sig, repl=""):
    global s
    a = s.index(a_sig); b = s.index(b_sig, a)
    s = s[:a] + repl + s[b:]
# 1. ethnl_upper_bits goes (only the ported functions use it)
cut("static u32 ethnl_upper_bits(unsigned int n)", "/**\n * ethnl_bitmap32_clear()")
# 2. clear, not_zero, update, test_bit -> prototypes
protos = '''/* RUST-PROTOS BEGIN: the u32-bitmap helpers and ethnl_bitset32_size() are in bitset_rs.rs. */
void ethnl_bitmap32_clear(u32 *dst, unsigned int start, unsigned int end, bool *mod);
bool ethnl_bitmap32_not_zero(const u32 *map, unsigned int start, unsigned int end);
void ethnl_bitmap32_update(u32 *dst, unsigned int nbits, const u32 *value, const u32 *mask, bool *mod);
bool ethnl_bitmap32_test_bit(const u32 *map, unsigned int index);
bool ethnl_bitmap32_equal(const u32 *map1, const u32 *map2, unsigned int nbits);

_Static_assert(ETH_GSTRING_LEN == 32 && NLA_HDRLEN == 4 && sizeof(bool) == 1, "bitset_rs.rs hard-codes these");
/* RUST-PROTOS END */

'''
cut("/**\n * ethnl_bitmap32_clear()", "/**\n * ethnl_bitset32_size()", protos)
# 3. ethnl_bitset32_size
cut("/**\n * ethnl_bitset32_size()", "/**\n * ethnl_put_bitset32()")
# 4. ethnl_bitmap32_equal
a = s.index("/**\n * ethnl_bitmap32_equal()")
k = s.index("static bool ethnl_bitmap32_equal("); b = s.index("\n}\n", k) + 3
s = s[:a] + s[b:].lstrip("\n")
note = "// SPDX-License-Identifier: GPL-2.0-only\n\n/*\n * RUST PORT (net/ethtool/bitset.c, 6.18.49): the u32-bitmap helpers and ethnl_bitset32_size() are in bitset_rs.rs. This file keeps the netlink attribute building and\n * parsing as upstream has it. Upstream's whole file is installed as bitset_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", note, 1)
open(sys.argv[2], "w").write(s)
