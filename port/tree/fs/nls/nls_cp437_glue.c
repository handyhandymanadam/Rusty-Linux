// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/nls/nls_cp437.c
 *
 * Charset cp437 translation tables.
 * Generated automatically from the Unicode and charset
 * tables from the Unicode Organization (www.unicode.org).
 * The Unicode to charset table has only exact mappings.
 *
 * RUST PORT (fs/nls/nls_cp437.c, 6.18.49). The tables, uni2char(), char2uni()
 * and the static struct nls_table are in nls_cp437_rs.rs. What stays here is
 * what a Rust body cannot express: the module_init/module_exit wrappers, the
 * MODULE_* metadata, and register_nls(), a macro that expands to
 * __register_nls(nls, THIS_MODULE) and so needs this module's identity.
 * Upstream's file is installed as nls_cp437_norust.c for CONFIG_RUST=n.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/nls.h>
#include <linux/errno.h>

/* Defined in nls_cp437_rs.rs; layout checked by rig/layout-check.sh. */
extern struct nls_table nls_cp437_rs_table;

static int __init init_nls_cp437(void)
{
	return register_nls(&nls_cp437_rs_table);
}

static void __exit exit_nls_cp437(void)
{
	unregister_nls(&nls_cp437_rs_table);
}

module_init(init_nls_cp437)
module_exit(exit_nls_cp437)

MODULE_DESCRIPTION("NLS Codepage 437 (United States, Canada)");
MODULE_LICENSE("Dual BSD/GPL");
