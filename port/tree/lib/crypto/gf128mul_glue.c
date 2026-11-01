/* gf128mul.c - GF(2^128) multiplication functions
 *
 * Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.
 * Copyright (c) 2006, Rik Snel <rsnel@cube.dyndns.org>
 *
 * Based on Dr Brian Gladman's (GPL'd) work published at
 * http://gladman.plushost.co.uk/oldsite/cryptography_technology/index.php
 * See the original copyright notice below.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 31/01/2006

 This file provides fast multiplication in GF(2^128) as required by several
 cryptographic authentication modes
*/

#include <crypto/gf128mul.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

/*
 * RUST PORT: the reduction tables, the multiplies by x and x^8, gf128mul_lle(),
 * and the FILL of the 4k/64k tables are in gf128mul_rs.rs. What stays here is
 * the ABI (all seven EXPORT_SYMBOLs, each a pass-through to a gf128mul_rs_*
 * function) and the allocation: kzalloc()/kfree_sensitive() are alloc_hooks
 * macros/inline wrappers over Kconfig-dependent state, so the allocate-or-fail
 * logic and gf128mul_free_64k() are upstream's, verbatim. The pure-C
 * (CONFIG_RUST=n) build is upstream's gf128mul.c, installed unmodified as
 * gf128mul_norust.c.
 */
void gf128mul_rs_x8_ble(le128 *r, const le128 *x);
void gf128mul_rs_lle(be128 *r, const be128 *b);
void gf128mul_rs_fill_64k_bbe(struct gf128mul_4k *const *t, const be128 *g);
void gf128mul_rs_64k_bbe(be128 *a, struct gf128mul_4k *const *t);
void gf128mul_rs_fill_4k_lle(struct gf128mul_4k *t, const be128 *g);
void gf128mul_rs_4k_lle(be128 *a, const struct gf128mul_4k *t);

void gf128mul_x8_ble(le128 *r, const le128 *x)
{
	gf128mul_rs_x8_ble(r, x);
}
EXPORT_SYMBOL(gf128mul_x8_ble);

void gf128mul_lle(be128 *r, const be128 *b)
{
	gf128mul_rs_lle(r, b);
}
EXPORT_SYMBOL(gf128mul_lle);

/* t[0][BYTE] contains g*BYTE, t[1][BYTE] g*x^8*BYTE .. t[15][BYTE] g*x^120*BYTE */
struct gf128mul_64k *gf128mul_init_64k_bbe(const be128 *g)
{
	struct gf128mul_64k *t;
	int i;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	for (i = 0; i < 16; i++) {
		t->t[i] = kzalloc(sizeof(*t->t[i]), GFP_KERNEL);
		if (!t->t[i]) {
			gf128mul_free_64k(t);
			t = NULL;
			goto out;
		}
	}

	gf128mul_rs_fill_64k_bbe(t->t, g);

out:
	return t;
}
EXPORT_SYMBOL(gf128mul_init_64k_bbe);

void gf128mul_free_64k(struct gf128mul_64k *t)
{
	int i;

	for (i = 0; i < 16; i++)
		kfree_sensitive(t->t[i]);
	kfree_sensitive(t);
}
EXPORT_SYMBOL(gf128mul_free_64k);

void gf128mul_64k_bbe(be128 *a, const struct gf128mul_64k *t)
{
	gf128mul_rs_64k_bbe(a, t->t);
}
EXPORT_SYMBOL(gf128mul_64k_bbe);

struct gf128mul_4k *gf128mul_init_4k_lle(const be128 *g)
{
	struct gf128mul_4k *t;

	t = kzalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	gf128mul_rs_fill_4k_lle(t, g);

out:
	return t;
}
EXPORT_SYMBOL(gf128mul_init_4k_lle);

void gf128mul_4k_lle(be128 *a, const struct gf128mul_4k *t)
{
	gf128mul_rs_4k_lle(a, t);
}
EXPORT_SYMBOL(gf128mul_4k_lle);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Functions for multiplying elements of GF(2^128)");
