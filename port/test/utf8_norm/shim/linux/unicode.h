#ifndef SHIM_UNICODE_H
#define SHIM_UNICODE_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define EXPORT_SYMBOL_GPL(x)
#define IS_MODULE(x) 0
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)
enum utf8_normalization { UTF8_NFDI = 0, UTF8_NFDICF, UTF8_NMAX };
struct utf8data; struct utf8data_table;
struct unicode_map {
	unsigned int version;
	const struct utf8data *ntab[UTF8_NMAX];
	const struct utf8data_table *tables;
};
#endif
