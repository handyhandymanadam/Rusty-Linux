// SPDX-License-Identifier: GPL-2.0
/*
 * glob(7) matching.
 *
 * PORTED TO RUST. The matcher itself is lib/glob_rs.rs; what remains here is
 * the two exported C entry symbols and their EXPORT_SYMBOL() lines.
 *
 * Why the wrappers are still C, deliberately:
 *
 *   glob_match() and glob_match_len() are EXPORT_SYMBOL(), not
 *   EXPORT_SYMBOL_GPL(). Rust symbols in this tree are exported GPL-only
 *   (rust/exports.c says so in as many words), and the loadable-module ABI
 *   is criterion 4. Keeping the two definitions in C keeps their signatures,
 *   their export licence and their MODVERSIONS CRCs bit-for-bit unchanged,
 *   so the port cannot change what a module sees. Every line of matching
 *   logic is nonetheless Rust.
 *
 * The original C body is preserved as the differential-test oracle in
 * port/test/glob/ref_glob.c and is not edited to agree with the Rust.
 */

#include <linux/module.h>
#include <linux/glob.h>

MODULE_DESCRIPTION("glob(7) matching");
MODULE_LICENSE("Dual MIT/GPL");

/* lib/glob_rs.rs */
bool rust_glob_match_str(char const *pat, char const *str, char const *str_end);

/**
 * glob_match - Shell-style pattern matching, like !fnmatch(pat, str, 0)
 * @pat: Shell-style pattern to match, e.g. "*.[ch]".
 * @str: String to match.  The pattern must match the entire string.
 *
 * Perform shell-style glob matching, returning true (1) if the match
 * succeeds, or false (0) if it fails.  Equivalent to !fnmatch(@pat, @str, 0).
 *
 * Pattern metacharacters are ?, *, [ and \.
 * (And, inside character classes, !, - and ].)
 *
 * This is small and simple implementation intended for device blacklists
 * where a string is matched against a number of patterns.  Thus, it
 * does not preprocess the patterns.  It is non-recursive, and run-time
 * is at most quadratic: strlen(@str)*strlen(@pat).
 *
 * An example of the worst case is glob_match("*aaaaa", "aaaaaaaaaa");
 * it takes 6 passes over the pattern before matching the string.
 *
 * Like !fnmatch(@pat, @str, 0) and unlike the shell, this does NOT
 * treat / or leading . specially; it isn't actually used for pathnames.
 *
 * Note that according to glob(7) (and unlike bash), character classes
 * are complemented by a leading !; this does not support the regex-style
 * [^a-z] syntax.
 *
 * An opening bracket without a matching close is matched literally.
 */
bool __pure glob_match(char const *pat, char const *str)
{
	return rust_glob_match_str(pat, str, NULL);
}
EXPORT_SYMBOL(glob_match);

/**
 * glob_match_len - glob match against a length-bounded string
 * @pat: Shell-style pattern to match.
 * @str: String to match.  Need not be NUL-terminated.
 * @len: Number of bytes of @str that may be read.
 *
 * Like glob_match(), but @str is only read up to @len bytes, so it can be
 * used on buffers that are not NUL-terminated (e.g. trace event fields).
 * A NUL byte within @len still terminates the string.
 */
bool __pure glob_match_len(char const *pat, char const *str, size_t len)
{
	return rust_glob_match_str(pat, str, str + len);
}
EXPORT_SYMBOL(glob_match_len);
