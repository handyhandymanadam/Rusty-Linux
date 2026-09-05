/* SPDX-License-Identifier: GPL-2.0
 *
 * The plist oracle. NOT a transcription: this compiles the pristine
 * lib/plist.c itself, with its names moved aside. See README.
 */
#define plist_add	ref_plist_add
#define plist_del	ref_plist_del
#define plist_requeue	ref_plist_requeue

#include "../../pristine/lib/plist.c"
