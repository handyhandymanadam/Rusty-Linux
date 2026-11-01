#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- ebitmap_glue.c = upstream security/selinux/ss/ebitmap.c without the bitmap functions (they are in ebitmap_rs.rs), plus the rust_eb_* wrappers."""
import sys
s = open(sys.argv[1]).read()
# 1. equal, cpy, and
a = s.index("bool ebitmap_equal("); b = s.index("#ifdef CONFIG_NETLABEL")
s = s[:a] + s[b:]
# 2. contains .. hash
a = s.index("/*\n * Check to see if all the bits set in e2 are also set in e1."); b = s.index("void __init ebitmap_cache_init(void)")
wrappers = r'''/* RUST-WRAPPERS BEGIN: what ebitmap_rs.rs asks of the kernel. */
void *rust_eb_node_alloc(int atomic);
void rust_eb_node_free(void *n);
u32 rust_eb_jhash_1word(u32 a, u32 initval);
u32 rust_eb_jhash(const void *key, u32 length, u32 initval);
void rust_eb_err(int which, u32 a, u32 b, u64 c);
void __noreturn rust_eb_bug(void);

/* The bitmap functions (equal, cpy, and, contains, get_bit, set_bit, destroy, read, write, hash) are in ebitmap_rs.rs; it hard-codes this node layout. */
static_assert(sizeof(struct ebitmap_node) == 64 && EBITMAP_UNIT_NUMS == 6 && EBITMAP_UNIT_SIZE == 64 && EBITMAP_SIZE == 384);
static_assert(offsetof(struct ebitmap_node, next) == 0 && offsetof(struct ebitmap_node, maps) == 8 && offsetof(struct ebitmap_node, startbit) == 56);
static_assert(sizeof(struct ebitmap) == 16 && offsetof(struct ebitmap, node) == 0 && offsetof(struct ebitmap, highbit) == 8);
static_assert(sizeof(struct policy_file) == 16 && offsetof(struct policy_file, data) == 0 && offsetof(struct policy_file, len) == 8);

void *rust_eb_node_alloc(int atomic)
{
	return kmem_cache_zalloc(ebitmap_node_cachep, atomic ? GFP_ATOMIC : GFP_KERNEL);
}

void rust_eb_node_free(void *n)
{
	kmem_cache_free(ebitmap_node_cachep, n);
}

u32 rust_eb_jhash_1word(u32 a, u32 initval)
{
	return jhash_1word(a, initval);
}

u32 rust_eb_jhash(const void *key, u32 length, u32 initval)
{
	return jhash(key, length, initval);
}

/* The pr_err() calls of ebitmap_read(), in the order of the rust numbering. */
void rust_eb_err(int which, u32 a, u32 b, u64 c)
{
	switch (which) {
	case 0:
		pr_err("SELinux: ebitmap: map size %u does not "
		       "match my size %u (high bit was %u)\n",
		       a, b, (u32)c);
		break;
	case 1:
		pr_err("SELinux: ebitmap: truncated map\n");
		break;
	case 2:
		pr_err("SELinux: ebitmap start bit (%u) is "
		       "not a multiple of the map unit size (%u)\n",
		       a, b);
		break;
	case 3:
		pr_err("SELinux: ebitmap start bit (%u) is "
		       "beyond the end of the bitmap (%u)\n",
		       a, b);
		break;
	case 4:
		pr_err("SELinux: ebitmap: out of memory\n");
		break;
	case 5:
		pr_err("SELinux: ebitmap: start bit %u"
		       " comes after start bit %u\n",
		       a, b);
		break;
	case 6:
		pr_err("SELinux: ebitmap: empty map\n");
		break;
	case 7:
		pr_err("SELinux: ebitmap: high bit %u is not equal to the expected value %zu\n",
		       a, (size_t)c);
		break;
	}
}

void __noreturn rust_eb_bug(void)
{
	BUG();
}
/* RUST-WRAPPERS END */

'''
s = s[:a] + wrappers + s[b:]
hdr = "// SPDX-License-Identifier: GPL-2.0\n"
note = "/* SPDX-License-Identifier: GPL-2.0 */\n/*\n * RUST PORT (security/selinux/ss/ebitmap.c, 6.18.49): the bitmap functions are in ebitmap_rs.rs. This file keeps the node cache, ebitmap_cache_init() and the NetLabel\n * import / export as upstream has them, plus the rust_eb_* wrappers. Upstream's whole file is installed as ebitmap_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("/* SPDX-License-Identifier: GPL-2.0 */\n", note, 1)
open(sys.argv[2], "w").write(s)
