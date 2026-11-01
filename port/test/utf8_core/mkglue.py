#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- utf8-core_glue.c = upstream fs/unicode/utf8-core.c with the comparison, folding and hashing functions turned into thunks over utf8_core_rs.rs."""
import sys
s = open(sys.argv[1]).read()
def body(sig_start, new_body):
    global s
    a = s.index(sig_start); b = s.index("{", a); e = s.index("\n}\n", b) + 3
    s = s[:b] + new_body + s[e - 2:]
body("int utf8_validate(", "{\n\treturn rust_utf8_validate(um, str->name, str->len);\n")
body("int utf8_strncmp(", "{\n\treturn rust_utf8_strncmp(um, s1->name, s1->len, s2->name, s2->len);\n")
body("int utf8_strncasecmp(", "{\n\treturn rust_utf8_strncasecmp(um, s1->name, s1->len, s2->name, s2->len);\n")
body("int utf8_strncasecmp_folded(", "{\n\treturn rust_utf8_strncasecmp_folded(um, cf->name, s1->name, s1->len);\n")
body("int utf8_casefold(", "{\n\treturn rust_utf8_casefold(um, str->name, str->len, dest, dlen);\n")
body("int utf8_casefold_hash(", "{\n\tu32 hash;\n\tint rc = rust_utf8_casefold_hash(um, salt, str->name, str->len, &hash);\n\n\tif (!rc)\n\t\tstr->hash = hash;\n\treturn rc;\n")
body("int utf8_normalize(", "{\n\treturn rust_utf8_normalize(um, str->name, str->len, dest, dlen);\n")
wr = r'''/* RUST-WRAPPERS BEGIN: the cursor loops are in utf8_core_rs.rs; the exported functions below are thunks over it. */
int rust_utf8_validate(const struct unicode_map *um, const unsigned char *name, unsigned int len);
int rust_utf8_strncmp(const struct unicode_map *um, const unsigned char *name1, unsigned int len1, const unsigned char *name2, unsigned int len2);
int rust_utf8_strncasecmp(const struct unicode_map *um, const unsigned char *name1, unsigned int len1, const unsigned char *name2, unsigned int len2);
int rust_utf8_strncasecmp_folded(const struct unicode_map *um, const unsigned char *cf, const unsigned char *name, unsigned int len);
int rust_utf8_casefold(const struct unicode_map *um, const unsigned char *name, unsigned int len, unsigned char *dest, size_t dlen);
int rust_utf8_normalize(const struct unicode_map *um, const unsigned char *name, unsigned int len, unsigned char *dest, size_t dlen);
int rust_utf8_casefold_hash(const struct unicode_map *um, const void *salt, const unsigned char *name, unsigned int len, u32 *hash);
u32 rust_u8c_end_name_hash(unsigned long hash);

u32 rust_u8c_end_name_hash(unsigned long hash)
{
	return end_name_hash(hash);
}
/* RUST-WRAPPERS END */

'''
a = s.index("int utf8_validate(")
s = s[:a] + wr + s[a:]
note = "/* SPDX-License-Identifier: GPL-2.0 */\n/*\n * RUST PORT (fs/unicode/utf8-core.c, 6.18.49): the cursor loops of the comparison, folding and hashing functions are in utf8_core_rs.rs; the exported functions stay here as thunks\n * (so their MODVERSIONS fingerprints keep coming from the C definitions). Upstream's whole file is installed as utf8-core_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("/* SPDX-License-Identifier: GPL-2.0 */\n", note, 1)
open(sys.argv[2], "w").write(s)
