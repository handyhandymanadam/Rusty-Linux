#pragma once
/* Routed through the same _printk() symbol the Rust side declares and
 * calls directly (see seq_buf_rs.rs's own header comment on why _printk()
 * rather than the printk() macro) -- one capture implementation in the
 * driver serves both language sides.
 */
int _printk(const char *fmt, ...);
#define printk(fmt, ...) _printk(fmt, ##__VA_ARGS__)
#define KERN_INFO ""
#define KERN_EMERG ""
#define KERN_ERR ""
#define KERN_WARNING ""

enum { DUMP_PREFIX_NONE, DUMP_PREFIX_ADDRESS, DUMP_PREFIX_OFFSET };

#include <linux/types.h>
int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize,
			char *linebuf, size_t linebuflen, bool ascii);
