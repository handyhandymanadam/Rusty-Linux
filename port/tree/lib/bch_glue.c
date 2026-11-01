/*
 * Generic binary BCH encoding/decoding library
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright © 2011 Parrot S.A.
 *
 * Author: Ivan Djelic <ivan.djelic@parrot.com>
 *
 * Description:
 *
 * This library provides runtime configurable encoding/decoding of binary
 * Bose-Chaudhuri-Hocquenghem (BCH) codes.
 *
 * Call bch_init to get a pointer to a newly allocated bch_control structure for
 * the given m (Galois field order), t (error correction capability) and
 * (optional) primitive polynomial parameters.
 *
 * Call bch_encode to compute and store ecc parity bytes to a given buffer.
 * Call bch_decode to detect and locate errors in received data.
 *
 * On systems supporting hw BCH features, intermediate results may be provided
 * to bch_decode in order to skip certain steps. See bch_decode() documentation
 * for details.
 *
 * Option CONFIG_BCH_CONST_PARAMS can be used to force fixed values of
 * parameters m and t; thus allowing extra compiler optimizations and providing
 * better (up to 2x) encoding performance. Using this option makes sense when
 * (m,t) are fixed and known in advance, e.g. when using BCH error correction
 * on a particular NAND flash device.
 *
 * Algorithmic details:
 *
 * Encoding is performed by processing 32 input bits in parallel, using 4
 * remainder lookup tables.
 *
 * The final stage of decoding involves the following internal steps:
 * a. Syndrome computation
 * b. Error locator polynomial computation using Berlekamp-Massey algorithm
 * c. Error locator root finding (by far the most expensive step)
 *
 * In this implementation, step c is not performed using the usual Chien search.
 * Instead, an alternative approach described in [1] is used. It consists in
 * factoring the error locator polynomial using the Berlekamp Trace algorithm
 * (BTA) down to a certain degree (4), after which ad hoc low-degree polynomial
 * solving techniques [2] are used. The resulting algorithm, called BTZ, yields
 * much better performance than Chien search for usual (m,t) values (typically
 * m >= 13, t < 32, see [1]).
 *
 * [1] B. Biswas, V. Herbert. Efficient root finding of polynomials over fields
 * of characteristic 2, in: Western European Workshop on Research in Cryptology
 * - WEWoRC 2009, Graz, Austria, LNCS, Springer, July 2009, to appear.
 * [2] [Zin96] V.A. Zinoviev. On the solution of equations of degree 10 over
 * finite fields GF(2^q). In Rapport de recherche INRIA no 2829, 1996.
 *
 * RUST PORT (lib/bch.c, 6.18.49): everything -- bch_encode, bch_decode, bch_init, bch_free and all the Galois-field and polynomial machinery under them --
 * is in bch_rs.rs. This file keeps the four exports as thunks (the MODVERSIONS fingerprint comes from the DWARF of the definition), kmalloc / kzalloc / kfree
 * as wrappers, the one WARN_ON site (the warning now names this file -- recorded divergence) and static assertions on the layout of struct bch_control that
 * the Rust mirrors. CONFIG_BCH_CONST_PARAMS (fixed m and t compiled in) and CONFIG_RUST=n build upstream's whole file, installed as bch_norust.c.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/bitrev.h>
#include <asm/byteorder.h>
#include <linux/bch.h>

static_assert(sizeof(unsigned long) == 8 && sizeof(bool) == 1);
static_assert(offsetof(struct bch_control, m) == 0 && offsetof(struct bch_control, n) == 4 && offsetof(struct bch_control, t) == 8 &&
	      offsetof(struct bch_control, ecc_bits) == 12 && offsetof(struct bch_control, ecc_bytes) == 16 &&
	      offsetof(struct bch_control, a_pow_tab) == 24 && offsetof(struct bch_control, a_log_tab) == 32 &&
	      offsetof(struct bch_control, mod8_tab) == 40 && offsetof(struct bch_control, ecc_buf) == 48 &&
	      offsetof(struct bch_control, ecc_buf2) == 56 && offsetof(struct bch_control, xi_tab) == 64 &&
	      offsetof(struct bch_control, syn) == 72 && offsetof(struct bch_control, cache) == 80 &&
	      offsetof(struct bch_control, elp) == 88 && offsetof(struct bch_control, poly_2t) == 96 &&
	      offsetof(struct bch_control, swap_bits) == 128);
extern const size_t rust_bch_ctl_size;
const size_t rust_bch_ctl_size = sizeof(struct bch_control);

void rust_bch_encode(struct bch_control *bch, const uint8_t *data, unsigned int len, uint8_t *ecc);
int rust_bch_decode(struct bch_control *bch, const uint8_t *data, unsigned int len, const uint8_t *recv_ecc, const uint8_t *calc_ecc,
		    const unsigned int *syn, unsigned int *errloc);
struct bch_control *rust_bch_init(int m, int t, unsigned int prim_poly, bool swap_bits);
void rust_bch_free(struct bch_control *bch);
void *rust_bchw_kmalloc(size_t size);
void *rust_bchw_kzalloc(size_t size);
void rust_bchw_kfree(void *p);
bool rust_bchw_warn_r_bytes(bool cond);

void *rust_bchw_kmalloc(size_t size) { return kmalloc(size, GFP_KERNEL); }
void *rust_bchw_kzalloc(size_t size) { return kzalloc(size, GFP_KERNEL); }
void rust_bchw_kfree(void *p) { kfree(p); }
bool rust_bchw_warn_r_bytes(bool cond) { return WARN_ON(cond); }

void bch_encode(struct bch_control *bch, const uint8_t *data,
		unsigned int len, uint8_t *ecc)
{
	rust_bch_encode(bch, data, len, ecc);
}
EXPORT_SYMBOL_GPL(bch_encode);

int bch_decode(struct bch_control *bch, const uint8_t *data, unsigned int len,
	       const uint8_t *recv_ecc, const uint8_t *calc_ecc,
	       const unsigned int *syn, unsigned int *errloc)
{
	return rust_bch_decode(bch, data, len, recv_ecc, calc_ecc, syn, errloc);
}
EXPORT_SYMBOL_GPL(bch_decode);

struct bch_control *bch_init(int m, int t, unsigned int prim_poly,
			     bool swap_bits)
{
	return rust_bch_init(m, t, prim_poly, swap_bits);
}
EXPORT_SYMBOL_GPL(bch_init);

void bch_free(struct bch_control *bch)
{
	rust_bch_free(bch);
}
EXPORT_SYMBOL_GPL(bch_free);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ivan Djelic <ivan.djelic@parrot.com>");
MODULE_DESCRIPTION("Binary BCH encoder/decoder");
