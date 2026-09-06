/* Stand-ins for the real, untouched kernel functions lib/seq_buf.c and
 * lib/seq_buf_rs.rs forward to. seq_write()/d_path()/mangle_path()/
 * hex_dump_to_buffer() back seq_buf_print_seq()/seq_buf_path()/
 * seq_buf_hex_dump() -- not differentially tested here (see driver.c's
 * header comment for why), so these just need to compile and link, not
 * behave with full fidelity. _printk() and test_copy_to_user() DO back a
 * differentially-tested function each (seq_buf_do_printk(),
 * seq_buf_to_user()) and are real enough to make that comparison
 * meaningful.
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>

struct seq_file;
struct path;

int seq_write(struct seq_file *seq, const void *data, size_t len)
{
	(void)seq; (void)data; (void)len;
	return 0;
}

char *mangle_path(char *s, const char *p, const char *esc)
{
	(void)esc;
	return (char *)p == s ? s : s;
}

char *d_path(const struct path *path, char *buf, int buflen)
{
	(void)path;
	if (buflen > 0)
		buf[0] = '\0';
	return buf;
}

int hex_dump_to_buffer(const void *buf, size_t len, int rowsize, int groupsize,
			char *linebuf, size_t linebuflen, bool ascii)
{
	(void)buf; (void)len; (void)rowsize; (void)groupsize; (void)ascii;
	if (linebuflen)
		linebuf[0] = '\0';
	return 0;
}

/* Real values -- lib/hexdump.c's hex_asc[], matching what hex_asc_hi()/lo()
 * in both the pristine reference and the Rust side index into. */
const char hex_asc[] = "0123456789abcdef";

/* _printk() capture: appends every formatted line, newline-separated, into
 * a growable buffer the driver can inspect. Shared by the pristine
 * reference (via the printk() macro -> _printk()) and the Rust side
 * (calls _printk() directly) -- same symbol, same capture, so the two
 * arms' output is compared the same way their buffer contents are. */
static char printk_capture[65536];
static size_t printk_capture_len;

int _printk(const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t remaining = sizeof(printk_capture) - printk_capture_len;

	if (remaining == 0)
		return 0;
	va_start(ap, fmt);
	n = vsnprintf(printk_capture + printk_capture_len, remaining, fmt, ap);
	va_end(ap);
	if (n > 0)
		printk_capture_len += (size_t)n < remaining ? (size_t)n : remaining - 1;
	return n;
}

const char *printk_capture_reset(void)
{
	printk_capture_len = 0;
	printk_capture[0] = '\0';
	return printk_capture;
}

/* A fixed "valid user range": copying into it is a real memcpy (success);
 * copying anywhere else fails exactly like an unmapped real user address
 * would, returning n (nothing copied) -- copy_to_user()'s real contract on
 * total failure. */
static unsigned char fake_user_buf[4096];

unsigned long test_copy_to_user(void *to, const void *from, unsigned long n)
{
	unsigned char *t = to;

	if (t >= fake_user_buf && t + n <= fake_user_buf + sizeof(fake_user_buf)) {
		memcpy(t, from, n);
		return 0;
	}
	return n;
}

void *test_copy_to_user_fake_buf(void)
{
	return fake_user_buf;
}

size_t test_copy_to_user_fake_buf_size(void)
{
	return sizeof(fake_user_buf);
}
