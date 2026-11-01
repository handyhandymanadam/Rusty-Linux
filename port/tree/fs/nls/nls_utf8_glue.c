// SPDX-License-Identifier: GPL-2.0
/*
 * Module for handling utf8 just like any other charset.
 * By Urban Widmark 2000
 *
 * RUST PORT (fs/nls/nls_utf8.c, 6.18.49). uni2char(), char2uni(), the
 * identity table and the static struct nls_table are in nls_utf8_rs.rs. What
 * stays here is what a Rust body cannot express: the module_init/module_exit
 * wrappers, the MODULE_* metadata, and register_nls(), a macro that expands
 * to __register_nls(nls, THIS_MODULE) and so needs this module's identity.
 * Upstream's file is installed as nls_utf8_norust.c for CONFIG_RUST=n.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/nls.h>
#include <linux/errno.h>

/* Defined in nls_utf8_rs.rs; layout checked by rig/layout-check.sh. */
extern struct nls_table nls_utf8_rs_table;

static int __init init_nls_utf8(void)
{
	return register_nls(&nls_utf8_rs_table);
}

static void __exit exit_nls_utf8(void)
{
	unregister_nls(&nls_utf8_rs_table);
}

module_init(init_nls_utf8)
module_exit(exit_nls_utf8)
MODULE_DESCRIPTION("NLS UTF-8");
MODULE_LICENSE("Dual BSD/GPL");
