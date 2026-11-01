// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/nls/nls_iso8859-1.c
 *
 * Charset iso8859-1 translation tables.
 * Generated automatically from the Unicode and charset
 * tables from the Unicode Organization (www.unicode.org).
 * The Unicode to charset table has only exact mappings.
 *
 * RUST PORT (fs/nls/nls_iso8859-1.c, 6.18.49). The tables, uni2char(), char2uni()
 * and the static struct nls_table are in nls_iso8859_1_rs.rs. What stays here is
 * what a Rust body cannot express: the module_init/module_exit wrappers, the
 * MODULE_* metadata, and register_nls(), a macro that expands to
 * __register_nls(nls, THIS_MODULE) and so needs this module's identity.
 * Upstream's file is installed as nls_iso8859-1_norust.c for CONFIG_RUST=n.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/nls.h>
#include <linux/errno.h>

/* Defined in nls_iso8859_1_rs.rs; layout checked by rig/layout-check.sh. */
extern struct nls_table nls_iso8859_1_rs_table;

static int __init init_nls_iso8859_1(void)
{
	return register_nls(&nls_iso8859_1_rs_table);
}

static void __exit exit_nls_iso8859_1(void)
{
	unregister_nls(&nls_iso8859_1_rs_table);
}

module_init(init_nls_iso8859_1)
module_exit(exit_nls_iso8859_1)

MODULE_DESCRIPTION("NLS ISO 8859-1 (Latin 1; Western European Languages)");
MODULE_LICENSE("Dual BSD/GPL");
