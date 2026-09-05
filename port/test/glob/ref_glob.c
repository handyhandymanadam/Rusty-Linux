/* SPDX-License-Identifier: GPL-2.0
 *
 * lib/glob.c's glob_match_str(), verbatim from linux-6.18.49 apart from the
 * kernel-isms that do not exist in userspace (__pure, fallthrough) and the
 * name, which is prefixed so both arms can be linked into one binary.
 *
 * This is the ORACLE. It is not edited to agree with the Rust; if the two
 * ever disagree the Rust is what changes.
 */
#include <stdbool.h>
#include <stddef.h>

bool ref_glob_match_str(char const *pat, char const *str, char const *str_end)
{
	char const *back_pat = NULL, *back_str = NULL;

	for (;;) {
		unsigned char c = (str_end && str >= str_end) ? '\0' : *str;
		unsigned char d = *pat++;

		str++;

		switch (d) {
		case '?':	/* Wildcard: anything but nul */
			if (c == '\0')
				return false;
			break;
		case '*':	/* Any-length wildcard */
			if (*pat == '\0')	/* Optimize trailing * case */
				return true;
			back_pat = pat;
			back_str = --str;	/* Allow zero-length match */
			break;
		case '[': {	/* Character class */
			if (c == '\0')	/* No possible match */
				return false;
			bool match = false, inverted = (*pat == '!');
			char const *class = pat + inverted;
			unsigned char a = *class++;

			do {
				unsigned char b = a;

				if (a == '\0')	/* Malformed */
					goto literal;

				if (class[0] == '-' && class[1] != ']') {
					b = class[1];

					if (b == '\0')
						goto literal;

					class += 2;
				}
				match |= (a <= c && c <= b);
			} while ((a = *class++) != ']');

			if (match == inverted)
				goto backtrack;
			pat = class;
			}
			break;
		case '\\':
			d = *pat++;
			/* fallthrough */
		default:	/* Literal character */
literal:
			if (c == d) {
				if (d == '\0')
					return true;
				break;
			}
backtrack:
			if (c == '\0' || !back_pat)
				return false;	/* No point continuing */
			/* Try again from last *, one character later in str. */
			pat = back_pat;
			str = ++back_str;
			break;
		}
	}
}
