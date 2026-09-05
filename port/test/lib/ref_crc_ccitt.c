/* SPDX-License-Identifier: GPL-2.0
 *
 * The CRC-CCITT oracle. NOT a transcription: this compiles the pristine
 * lib/crc/crc-ccitt.c itself, with the function name moved aside. The TABLE
 * keeps its real name, because that is the same table the port is handed a
 * pointer to in the kernel -- one copy, not two. See README.
 */
#define crc_ccitt	ref_crc_ccitt

#include "../../pristine/lib/crc/crc-ccitt.c"
