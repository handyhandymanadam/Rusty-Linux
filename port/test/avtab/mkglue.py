#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- avtab_glue.c = upstream security/selinux/ss/avtab.c without the table functions (they are in avtab_rs.rs), plus the rust_av_* wrappers."""
import sys
s = open(sys.argv[1]).read()
wrappers = r'''/* RUST-WRAPPERS BEGIN: what avtab_rs.rs asks of the kernel. */
void *rust_av_node_alloc(void);
void rust_av_node_free(void *n);
void *rust_av_xperms_alloc(void);
void rust_av_xperms_free(void *x);
void *rust_av_kvcalloc(u32 n);
void rust_av_kvfree(void *p);
int rust_av_type_isvalid(const void *pol, u32 t);
int rust_av_class_isvalid(const void *pol, u32 c);
u32 rust_av_policyvers(const void *pol);
void rust_av_err(int which, u32 a, u32 b);
void rust_av_warn_xperm(const void *pol, u8 specified);

/* The table functions (hash, insert, search, destroy, alloc, read, write) are in avtab_rs.rs; it hard-codes these layouts and the values of the AVTAB_* flags. */
static_assert(sizeof(struct avtab_key) == 8 && offsetof(struct avtab_key, source_type) == 0 && offsetof(struct avtab_key, target_type) == 2 && offsetof(struct avtab_key, target_class) == 4 &&
	      offsetof(struct avtab_key, specified) == 6);
static_assert(sizeof(struct avtab_extended_perms) == 36 && offsetof(struct avtab_extended_perms, specified) == 0 && offsetof(struct avtab_extended_perms, driver) == 1 &&
	      offsetof(struct avtab_extended_perms, perms) == 4 && ARRAY_SIZE(((struct avtab_extended_perms *)0)->perms.p) == 8);
static_assert(sizeof(struct avtab_datum) == 8 && sizeof(struct avtab_node) == 24 && offsetof(struct avtab_node, key) == 0 && offsetof(struct avtab_node, datum) == 8 &&
	      offsetof(struct avtab_node, next) == 16);
static_assert(sizeof(struct avtab) == 24 && offsetof(struct avtab, htable) == 0 && offsetof(struct avtab, nel) == 8 && offsetof(struct avtab, nslot) == 12 && offsetof(struct avtab, mask) == 16);
static_assert(sizeof(struct policy_file) == 16 && offsetof(struct policy_file, data) == 0 && offsetof(struct policy_file, len) == 8);
static_assert(AVTAB_ALLOWED == 1 && AVTAB_AUDITALLOW == 2 && AVTAB_AUDITDENY == 4 && AVTAB_TRANSITION == 0x10 && AVTAB_MEMBER == 0x20 && AVTAB_CHANGE == 0x40 &&
	      AVTAB_XPERMS_ALLOWED == 0x100 && AVTAB_XPERMS_AUDITALLOW == 0x200 && AVTAB_XPERMS_DONTAUDIT == 0x400 && AVTAB_ENABLED == 0x8000 && AVTAB_ENABLED_OLD == 0x80000000 &&
	      AVTAB_SPECIFIER_MASK == 0x8777 && AVTAB_XPERMS_IOCTLFUNCTION == 1 && AVTAB_XPERMS_IOCTLDRIVER == 2 && AVTAB_XPERMS_NLMSG == 3);
static_assert(POLICYDB_VERSION_AVTAB == 20 && POLICYDB_VERSION_XPERMS_IOCTL == 30 && POLICYDB_VERSION_COND_XPERMS == 34 && MAX_AVTAB_HASH_BUCKETS == 65536);

void *rust_av_node_alloc(void)
{
	return kmem_cache_zalloc(avtab_node_cachep, GFP_KERNEL);
}

void rust_av_node_free(void *n)
{
	kmem_cache_free(avtab_node_cachep, n);
}

void *rust_av_xperms_alloc(void)
{
	return kmem_cache_zalloc(avtab_xperms_cachep, GFP_KERNEL);
}

void rust_av_xperms_free(void *x)
{
	kmem_cache_free(avtab_xperms_cachep, x);
}

void *rust_av_kvcalloc(u32 n)
{
	return kvcalloc(n, sizeof(void *), GFP_KERNEL);
}

void rust_av_kvfree(void *p)
{
	kvfree(p);
}

int rust_av_type_isvalid(const void *pol, u32 t)
{
	return policydb_type_isvalid((struct policydb *)pol, t);
}

int rust_av_class_isvalid(const void *pol, u32 c)
{
	return policydb_class_isvalid((struct policydb *)pol, c);
}

u32 rust_av_policyvers(const void *pol)
{
	return ((const struct policydb *)pol)->policyvers;
}

/* The pr_err() calls of avtab_read_item() and avtab_read(), in the order of the rust numbering. */
void rust_av_err(int which, u32 a, u32 b)
{
	switch (which) {
	case 0:
		pr_err("SELinux: avtab: truncated entry\n");
		break;
	case 1:
		pr_err("SELinux: avtab: invalid item count\n");
		break;
	case 2:
		pr_err("SELinux: avtab: truncated source type\n");
		break;
	case 3:
		pr_err("SELinux: avtab: truncated target type\n");
		break;
	case 4:
		pr_err("SELinux: avtab: truncated target class\n");
		break;
	case 5:
		pr_err("SELinux: avtab: invalid type or class\n");
		break;
	case 6:
		pr_err("SELinux: avtab: null entry\n");
		break;
	case 7:
		pr_err("SELinux: avtab: entry has both access vectors and types\n");
		break;
	case 8:
		pr_err("SELinux: avtab: entry has extended permissions\n");
		break;
	case 9:
		pr_err("SELinux: avtab: entry has too many items (%d/%d)\n",
		       a, b);
		break;
	case 10:
		pr_err("SELinux: avtab: entry only had %d items, expected %d\n",
		       a, b);
		break;
	case 11:
		pr_err("SELinux:  avtab:  not exactly one specifier\n");
		break;
	case 12:
		pr_err("SELinux:  avtab:  invalid specifier\n");
		break;
	case 13:
		pr_err("SELinux:  avtab:  policy version %u does not "
		       "support extended permissions rules and one "
		       "was specified\n",
		       a);
		break;
	case 14:
		pr_err("SELinux:  avtab:  policy version %u does not "
		       "support extended permissions rules in conditional "
		       "policies and one was specified\n",
		       a);
		break;
	case 15:
		pr_err("SELinux: avtab: invalid type\n");
		break;
	case 16:
		pr_err("SELinux: avtab: out of memory\n");
		break;
	case 17:
		pr_err("SELinux: avtab: duplicate entry\n");
		break;
	case 18:
		pr_err("SELinux: avtab: truncated table\n");
		break;
	case 19:
		pr_err("SELinux: avtab: table is empty\n");
		break;
	}
}

void rust_av_warn_xperm(const void *pol, u8 specified)
{
	pr_warn_once_policyload((struct policydb *)pol,
				"SELinux: avtab: unsupported xperm specifier %#x\n",
				specified);
}
/* RUST-WRAPPERS END */

/* lib/libtest.c builds a policydb by hand at these offsets (it cannot include policydb.h). */
static_assert(sizeof(struct policydb) == 608 && offsetof(struct policydb, policyvers) == 592 && offsetof(struct policydb, p_types.nprim) == 96 && offsetof(struct policydb, p_classes.nprim) == 48);

'''
a = s.index("/* Based on MurmurHash3"); b = s.index("#ifdef CONFIG_SECURITY_SELINUX_DEBUG")
s = s[:a] + wrappers + s[b:]
a = s.index("/* clang-format off */"); b = s.index("void __init avtab_cache_init(void)")
s = s[:a] + s[b:]
note = "/* SPDX-License-Identifier: GPL-2.0-only */\n/*\n * RUST PORT (security/selinux/ss/avtab.c, 6.18.49): the table functions are in avtab_rs.rs. This file keeps the slab caches, avtab_cache_init(), avtab_hash_eval() (debug only)\n * and the rust_av_* wrappers. Upstream's whole file is installed as avtab_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("/* SPDX-License-Identifier: GPL-2.0-only */\n", note, 1)
open(sys.argv[2], "w").write(s)
