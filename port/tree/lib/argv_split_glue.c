// SPDX-License-Identifier: GPL-2.0
/*
 * RUST PORT (lib/argv_split.c, 6.18.49): count_argc(), argv_free() and argv_split() are in argv_split_rs.rs. This file keeps the exports as thunks (the MODVERSIONS
 * fingerprint comes from the DWARF of the definition) and the allocator wrappers (kstrndup() with KMALLOC_MAX_SIZE, kmalloc_array(), kfree()). Upstream's whole
 * file is installed as argv_split_norust.c for CONFIG_RUST=n.
 */
/*
 * Helper function for splitting a string into an argv-like array.
 */

#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/export.h>


char **rust_argv_split(gfp_t gfp, const char *str, int *argcp);
void rust_argv_free(char **argv);
char *rust_as_kstrndup(const char *s, gfp_t gfp);
char **rust_as_kmalloc_array(size_t n, gfp_t gfp);
void rust_as_kfree(const void *p);

char *rust_as_kstrndup(const char *s, gfp_t gfp) { return kstrndup(s, KMALLOC_MAX_SIZE - 1, gfp); }
char **rust_as_kmalloc_array(size_t n, gfp_t gfp) { return kmalloc_array(n, sizeof(char *), gfp); }
void rust_as_kfree(const void *p) { kfree(p); }

/**
 * argv_free - free an argv
 * @argv: the argument vector to be freed
 *
 * Frees an argv and the strings it points to.
 */
void argv_free(char **argv)
{
	rust_argv_free(argv);
}
EXPORT_SYMBOL(argv_free);

/**
 * argv_split - split a string at whitespace, returning an argv
 * @gfp: the GFP mask used to allocate memory
 * @str: the string to be split
 * @argcp: returned argument count
 *
 * Returns: an array of pointers to strings which are split out from
 * @str.  This is performed by strictly splitting on white-space; no
 * quote processing is performed.  Multiple whitespace characters are
 * considered to be a single argument separator.  The returned array
 * is always NULL-terminated.  Returns NULL on memory allocation
 * failure.
 *
 * The source string at `str' may be undergoing concurrent alteration via
 * userspace sysctl activity (at least).  The argv_split() implementation
 * attempts to handle this gracefully by taking a local copy to work on.
 */
char **argv_split(gfp_t gfp, const char *str, int *argcp)
{
	return rust_argv_split(gfp, str, argcp);
}
EXPORT_SYMBOL(argv_split);
