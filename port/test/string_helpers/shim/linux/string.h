/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SHIM_LINUX_STRING_H
#define _SHIM_LINUX_STRING_H
#include <string.h>
#include <stdbool.h>
#include <stddef.h>

extern char *skip_spaces(const char *);
extern char *strim(char *);
char *strreplace(char *str, char old, char new);
extern bool sysfs_streq(const char *s1, const char *s2);
int match_string(const char * const *array, size_t n, const char *string);
int __sysfs_match_string(const char * const *array, size_t n, const char *s);
void memcpy_and_pad(void *dest, size_t dest_len, const void *src, size_t count, int pad);

/* declared here in the real kernel via linux/uaccess.h / mm.h; string_helpers.c
 * pulls it in transitively without including uaccess.h directly. */
extern char *memdup_user_nul(const char *src, size_t len);

#endif
