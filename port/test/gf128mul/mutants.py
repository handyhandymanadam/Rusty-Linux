#!/usr/bin/env python3
"""mutants.py FILE N OUT -- write FILE with mutant N applied (first occurrence).
Prints the mutant's name; exit 3 when N is past the end. Mutants of
gf128mul_rs.rs are numbered from 1; glue mutants (FILE = gf128mul_glue.c) are
selected with the same N against GLUE below."""
import sys
RS = [
 ("lle reduction constant 0xe1->0xe0", "(0xe1 << 56)", "(0xe0 << 56)"),
 ("bbe reduction constant 0x87->0x86", "(m & 0x87)", "(m & 0x86)"),
 ("xda_le coefficient 0x01c2->0x01c3", "* 0x01c2)", "* 0x01c3)"),
 ("xda_be coefficient 0x4380->0x4381", "* 0x4380)", "* 0x4381)"),
 ("xda_le coefficient 0x7080->0x7081", "* 0x7080)", "* 0x7081)"),
 ("x8_lle shift a<<56->a<<55", "{\n    (b >> 8) | (a << 56)", "{\n    (b >> 8) | (a << 55)"),
 ("x8_be_b or instead of xor", "{\n    (b << 8) ^ tt", "{\n    (b << 8) | tt"),
 ("endianness: store_be writes little-endian b", "(*p).b = b.to_be();", "(*p).b = b.to_le();"),
 ("endianness: x8_ble stores a big-endian", "(*r).a = x8_be_a(a, b, tt).to_le();", "(*r).a = x8_be_a(a, b, tt).to_be();"),
 ("endianness: load_be reads a little-endian", "(u64::from_be((*p).a), u64::from_be((*p).b))", "(u64::from_le((*p).a), u64::from_be((*p).b))"),
 ("x8_ble uses the le table", "TABLE_BE[(a >> 56) as usize] as u64;\n\n        (*r).a", "TABLE_LE[(a >> 56) as usize] as u64;\n\n        (*r).a"),
 ("table builder swapped le/be", "if le { xda_le(i as u64) } else { xda_be(i as u64) }", "if !le { xda_le(i as u64) } else { xda_be(i as u64) }"),
 ("lle wrong index select (bit 0x40 inverted)", "p.add(2 + usize::from(ch & 0x40 == 0))", "p.add(2 + usize::from(ch & 0x40 != 0))"),
 ("lle odd entries not zero", "x_lle(p.add(2 * i + 2), p.add(2 * i));", "x_lle(p.add(2 * i + 2), p.add(2 * i)); *p.add(2 * i + 1) = *p.add(2 * i);"),
 ("lle 15 byte rounds instead of 16", "if i >= 16 {\n                break;\n            }\n\n            x8_lle_ti", "if i >= 15 {\n                break;\n            }\n\n            x8_lle_ti"),
 ("lle reads b bytes in the wrong order", "b.cast::<u8>().add(15 - i)", "b.cast::<u8>().add(i)"),
 ("lle skips p doubling count (6 not 7)", "for i in 0..7 {", "for i in 0..6 {"),
 ("4k fill starts at j=32", "let mut j = 64usize;\n        while j > 0 {\n            x_lle", "let mut j = 32usize;\n        while j > 0 {\n            x_lle"),
 ("4k fill xor operand off", "be128_xor(tab.add(j + k), tab.add(j), tab.add(k));", "be128_xor(tab.add(j + k), tab.add(j), tab.add(k ^ 1));"),
 ("4k mult starts at byte 14", "let mut i = 15usize;\n        while i > 0 {\n            i -= 1;\n            x8_lle(rp);", "let mut i = 14usize;\n        while i > 0 {\n            i -= 1;\n            x8_lle(rp);"),
 ("4k mult byte order", "tab.add(*ap.add(i) as usize));", "tab.add(*ap.add(15 - i) as usize));"),
 ("64k fill j<64 not <=64", "while j <= 64 {", "while j < 64 {"),
 ("64k fill applies x8 twice", "x8_bbe(tab(i, j));", "x8_bbe(tab(i, j)); x8_bbe(tab(i, j));"),
 ("64k fill copies from wrong table", "*tab(i, j) = *tab(i - 1, j);", "*tab(i, j) = *tab(0, j);"),
 ("64k mult 14 tables", "for i in 1..16 {\n            be128_xor(rp, rp, ent(i,", "for i in 1..15 {\n            be128_xor(rp, rp, ent(i,"),
 ("64k mult byte order", "ent(i, *ap.add(15 - i))", "ent(i, *ap.add(i))"),
]
GLUE = [
 ("glue: init_64k failure path does not free", "\t\t\tgf128mul_free_64k(t);\n\t\t\tt = NULL;", "\t\t\tt = NULL;"),
 ("glue: free_64k frees 15 tables", "for (i = 0; i < 16; i++)\n\t\tkfree_sensitive(t->t[i]);", "for (i = 0; i < 15; i++)\n\t\tkfree_sensitive(t->t[i]);"),
 ("glue: init_64k allocates 15 sub-tables", "\tfor (i = 0; i < 16; i++) {\n\t\tt->t[i] = kzalloc", "\tfor (i = 0; i < 15; i++) {\n\t\tt->t[i] = kzalloc"),
]
f, n, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
M = GLUE if f.endswith(".c") else RS
if n > len(M): sys.exit(3)
name, a, b = M[n - 1]
s = open(f).read()
assert s.count(a) >= 1, "mutant pattern absent: " + name
open(out, "w").write(s.replace(a, b, 1))
print(name)
