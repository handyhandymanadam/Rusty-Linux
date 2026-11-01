#!/usr/bin/env python3
"""mkglue.py hashtab PRISTINE.c OUT.c | mkglue.py symtab PRISTINE.c OUT.c -- the C that remains of security/selinux/ss/hashtab.c / symtab.c once hashtab_rs.rs / symtab_rs.rs hold the code."""
import sys
which, src, out = sys.argv[1:4]
s = open(src).read()
if which == "hashtab":
    wrappers = r'''/* RUST-WRAPPERS BEGIN: what hashtab_rs.rs asks of the kernel. */
struct hashtab_node *rust_ht_node_alloc(void);
void rust_ht_node_free(struct hashtab_node *n);
void *rust_ht_kcalloc_nowarn(u32 n);
void *rust_ht_kcalloc(u32 n);
void rust_ht_kfree(void *p);

/* The table functions are in hashtab_rs.rs; it hard-codes these layouts. */
static_assert(sizeof(struct hashtab_node) == 24 && offsetof(struct hashtab_node, key) == 0 && offsetof(struct hashtab_node, datum) == 8 && offsetof(struct hashtab_node, next) == 16);
static_assert(sizeof(struct hashtab) == 16 && offsetof(struct hashtab, htable) == 0 && offsetof(struct hashtab, size) == 8 && offsetof(struct hashtab, nel) == 12);

struct hashtab_node *rust_ht_node_alloc(void)
{
	return kmem_cache_zalloc(hashtab_node_cachep, GFP_KERNEL);
}

void rust_ht_node_free(struct hashtab_node *n)
{
	kmem_cache_free(hashtab_node_cachep, n);
}

void *rust_ht_kcalloc_nowarn(u32 n)
{
	return kcalloc(n, sizeof(struct hashtab_node *), GFP_KERNEL | __GFP_NOWARN);
}

void *rust_ht_kcalloc(u32 n)
{
	return kcalloc(n, sizeof(struct hashtab_node *), GFP_KERNEL);
}

void rust_ht_kfree(void *p)
{
	kfree(p);
}
/* RUST-WRAPPERS END */

'''
    a = s.index("static u32 hashtab_compute_size("); b = s.index("#ifdef CONFIG_SECURITY_SELINUX_DEBUG")
    s = s[:a] + wrappers + s[b:]
    a = s.index("int hashtab_duplicate("); b = s.index("void __init hashtab_cache_init(void)")
    s = s[:a] + s[b:]
    s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (security/selinux/ss/hashtab.c, 6.18.49): the table functions are in hashtab_rs.rs. This file keeps the node cache, hashtab_cache_init(), hashtab_stat() (debug only)\n * and the rust_ht_* wrappers. Upstream's whole file is installed as hashtab_norust.c for CONFIG_RUST=n.\n */\n", 1)
else:
    a = s.index("static unsigned int symhash(")
    wrappers = r'''/* RUST-WRAPPERS BEGIN: what symtab_rs.rs asks of the kernel. */
void rust_st_cond_resched(void);

/* symtab_rs.rs hard-codes these layouts (and the hash and compare of upstream's symtab_key_params). */
static_assert(sizeof(struct symtab) == 24 && offsetof(struct symtab, table) == 0 && offsetof(struct symtab, nprim) == 16);

void rust_st_cond_resched(void)
{
	cond_resched();
}
/* RUST-WRAPPERS END */
'''
    s = s[:a] + wrappers
    s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (security/selinux/ss/symtab.c, 6.18.49): the whole file is in symtab_rs.rs; this file keeps the layout checks and the cond_resched() wrapper.\n * Upstream's file is installed as symtab_norust.c for CONFIG_RUST=n.\n */\n", 1)
open(out, "w").write(s)
