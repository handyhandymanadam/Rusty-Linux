// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/parser.c - simple parser for mount, etc. options.
 */

#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/export.h>
#include <linux/kstrtox.h>
#include <linux/parser.h>
#include <linux/slab.h>
#include <linux/string.h>

/*
 * max size needed by different bases to express U64
 * HEX: "0xFFFFFFFFFFFFFFFF" --> 18
 * DEC: "18446744073709551615" --> 20
 * OCT: "01777777777777777777777" --> 23
 * pick the max one to define NUMBER_BUF_LEN
 */
/*
 * RUST PORT (lib/parser.c, 6.18.49): match_token() and its helpers, match_int/uint/u64/octal/hex, match_wildcard and
 * match_strlcpy, with their EXPORT_SYMBOLs, are in parser_rs.rs. Only match_strdup() stays here (kmemdup_nul is a slab
 * call). Upstream's file is installed as parser_norust.c for CONFIG_RUST=n.
 */

/**
 * match_strdup - allocate a new string with the contents of a substring_t
 * @s: &substring_t to copy
 *
 * Description: Allocates and returns a string filled with the contents of
 * the &substring_t @s. The caller is responsible for freeing the returned
 * string with kfree().
 *
 * Return: the address of the newly allocated NUL-terminated string or
 * %NULL on error.
 */
char *match_strdup(const substring_t *s)
{
	return kmemdup_nul(s->from, s->to - s->from, GFP_KERNEL);
}
EXPORT_SYMBOL(match_strdup);
