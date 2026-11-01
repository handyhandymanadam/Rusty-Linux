/* SPDX-License-Identifier: GPL-2.0 */
/* Real content, matching include/linux/string_helpers.h. */
#ifndef _SHIM_LINUX_STRING_HELPERS_H_
#define _SHIM_LINUX_STRING_HELPERS_H_

#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/types.h>

struct device;
struct file;
struct task_struct;

enum string_size_units {
	STRING_UNITS_10,
	STRING_UNITS_2,
	STRING_UNITS_MASK	= 1,

	STRING_UNITS_NO_SPACE	= 1u << 30,
	STRING_UNITS_NO_BYTES	= 1u << 31,
};

int string_get_size(u64 size, u64 blk_size, const enum string_size_units units,
		    char *buf, int len);

int parse_int_array(const char *buf, size_t count, int **array);
int parse_int_array_user(const char *from, size_t count, int **array);

#define UNESCAPE_SPACE		(1u << 0)
#define UNESCAPE_OCTAL		(1u << 1)
#define UNESCAPE_HEX		(1u << 2)
#define UNESCAPE_SPECIAL	(1u << 3)
#define UNESCAPE_ANY		\
	(UNESCAPE_SPACE | UNESCAPE_OCTAL | UNESCAPE_HEX | UNESCAPE_SPECIAL)

int string_unescape(char *src, char *dst, size_t size, unsigned int flags);

#define ESCAPE_SPACE		(1u << 0)
#define ESCAPE_SPECIAL		(1u << 1)
#define ESCAPE_NULL		(1u << 2)
#define ESCAPE_OCTAL		(1u << 3)
#define ESCAPE_ANY		\
	(ESCAPE_SPACE | ESCAPE_OCTAL | ESCAPE_SPECIAL | ESCAPE_NULL)
#define ESCAPE_NP		(1u << 4)
#define ESCAPE_ANY_NP		(ESCAPE_ANY | ESCAPE_NP)
#define ESCAPE_HEX		(1u << 5)
#define ESCAPE_NA		(1u << 6)
#define ESCAPE_NAP		(1u << 7)
#define ESCAPE_APPEND		(1u << 8)

int string_escape_mem(const char *src, size_t isz, char *dst, size_t osz,
		unsigned int flags, const char *only);

char *kstrdup_quotable(const char *src, gfp_t gfp);
char *kstrdup_quotable_cmdline(struct task_struct *task, gfp_t gfp);
char *kstrdup_quotable_file(struct file *file, gfp_t gfp);

char *kstrdup_and_replace(const char *src, char old, char new, gfp_t gfp);

char **kasprintf_strarray(gfp_t gfp, const char *prefix, size_t n);
void kfree_strarray(char **array, size_t n);

char **devm_kasprintf_strarray(struct device *dev, const char *prefix, size_t n);

#endif
