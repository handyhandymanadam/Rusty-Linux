/* SPDX-License-Identifier: GPL-2.0
 *
 * The ARC4 oracle. NOT a transcription: this compiles the pristine
 * lib/crypto/arc4.c itself, with its names moved aside. See README.
 */
#define arc4_setkey	ref_arc4_setkey
#define arc4_crypt	ref_arc4_crypt

#include "../../pristine/lib/crypto/arc4.c"
