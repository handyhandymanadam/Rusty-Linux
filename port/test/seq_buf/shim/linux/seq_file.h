#pragma once
#include <linux/types.h>

/* Minimal -- seq_buf_print_seq()/seq_buf_path() are not differentially
 * tested here (thin pass-throughs to real, independently-verified
 * kernel functions; see lib/seq_buf_rs.rs's own module doc and this
 * harness's driver.c header comment). This only needs to COMPILE.
 */
struct seq_file {
	char *buf;
	size_t size;
	size_t count;
};

struct path;

int seq_write(struct seq_file *seq, const void *data, size_t len);
char *mangle_path(char *s, const char *p, const char *esc);
char *d_path(const struct path *path, char *buf, int buflen);
