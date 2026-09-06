/* Differential test for lib/seq_buf.c -> lib/seq_buf_rs.rs.
 *
 * Scope: the six functions whose OWN logic is real, non-trivial arithmetic
 * -- seq_buf_puts/putc/putmem/putmem_hex (bounds/overflow bookkeeping),
 * seq_buf_do_printk (the strchr-based line splitter), seq_buf_to_user (the
 * start/cnt clamping and copy_to_user()-result handling). Compared against
 * the pristine C, renamed to *_c_ref.
 *
 * NOT covered here, deliberately: seq_buf_print_seq()/seq_buf_path()/
 * seq_buf_hex_dump() are near-total pass-throughs to seq_write()/
 * d_path()+mangle_path()/hex_dump_to_buffer() -- real kernel functions this
 * port does not touch, stubbed to a bare minimum here just so the file
 * compiles (see stubs.c's header comment). Their OWN reachability and
 * real-subsystem behavior is already exercised for real, in the actual
 * kernel, by lib/libtest.c's test_seq_buf() (a real struct seq_file, a real
 * struct path via get_fs_root(), real hex_dump_to_buffer() -- already
 * covered by hexdump.c's own 1000s-case differential). seq_buf_bprintf()
 * is CONFIG_BINARY_PRINTF-gated and not compiled into this harness at all
 * (same reasoning: thin pass-through to bstr_printf(), tested for real via
 * libtest instead).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct seq_buf { char *buffer; size_t size; size_t len; };

static inline void seq_buf_init(struct seq_buf *s, char *buf, unsigned int size)
{
	s->buffer = buf;
	s->size = size;
	s->len = 0;
	if (size) buf[0] = 0;
}
static inline int seq_buf_overflowed(struct seq_buf *s) { return s->len > s->size; }

/* Pristine reference (renamed at compile time, see run.sh). */
extern int seq_buf_puts_c_ref(struct seq_buf *s, const char *str);
extern int seq_buf_putc_c_ref(struct seq_buf *s, unsigned char c);
extern int seq_buf_putmem_c_ref(struct seq_buf *s, const void *mem, unsigned int len);
extern int seq_buf_putmem_hex_c_ref(struct seq_buf *s, const void *mem, unsigned int len);
extern void seq_buf_do_printk_c_ref(struct seq_buf *s, const char *lvl);
extern int seq_buf_to_user_c_ref(struct seq_buf *s, void *ubuf, size_t start, int cnt);

/* The port (Rust, real names). */
extern int seq_buf_puts(struct seq_buf *s, const char *str);
extern int seq_buf_putc(struct seq_buf *s, unsigned char c);
extern int seq_buf_putmem(struct seq_buf *s, const void *mem, unsigned int len);
extern int seq_buf_putmem_hex(struct seq_buf *s, const void *mem, unsigned int len);
extern void seq_buf_do_printk(struct seq_buf *s, const char *lvl);
extern int seq_buf_to_user(struct seq_buf *s, void *ubuf, size_t start, int cnt);

extern const char *printk_capture_reset(void);
extern void *test_copy_to_user_fake_buf(void);
extern size_t test_copy_to_user_fake_buf_size(void);

static unsigned checks, fails;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		fails++;
		fprintf(stderr, "MISMATCH: %s\n", what);
	}
}

static uint32_t rng_state;
static uint32_t xrand(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

#define BUFCAP 64

static void one_scenario(void)
{
	char cbuf[BUFCAP], rbuf[BUFCAP];
	struct seq_buf cs, rs;
	unsigned bufsz = xrand() % (BUFCAP + 4); /* deliberately can exceed BUFCAP: prove-can-fail lever */
	if (bufsz > BUFCAP) bufsz = BUFCAP;
	unsigned prefix_len = xrand() % (bufsz + 2);

	/* Both sides' uninitialized trailing bytes (past whatever gets
	 * actually written) must match, or the byte-for-byte compare below
	 * reports a false mismatch from stack garbage, not a real one. */
	memset(cbuf, 0, sizeof(cbuf));
	memset(rbuf, 0, sizeof(rbuf));

	seq_buf_init(&cs, cbuf, bufsz);
	seq_buf_init(&rs, rbuf, bufsz);

	/* Put both sides in the same, possibly-nonzero, starting state so
	 * overflow near the boundary is exercised, not just from empty. */
	{
		char prefix[BUFCAP + 2];
		unsigned i;
		for (i = 0; i < prefix_len && i < sizeof(prefix) - 1; i++)
			prefix[i] = 'A' + (xrand() % 26);
		prefix[i < sizeof(prefix) - 1 ? i : sizeof(prefix) - 1] = 0;
		int rc = seq_buf_puts_c_ref(&cs, prefix);
		int rr = seq_buf_puts(&rs, prefix);
		check(rc == rr, "prefix seeding: puts return value matches");
	}

	int case_idx = xrand() % 6;
	switch (case_idx) {
	case 0: { /* puts */
		char str[16];
		unsigned len = xrand() % 12, i;
		for (i = 0; i < len; i++) str[i] = 'a' + (xrand() % 26);
		str[len] = 0;
		int rc = seq_buf_puts_c_ref(&cs, str);
		int rr = seq_buf_puts(&rs, str);
		check(rc == rr, "puts: return value");
		break;
	}
	case 1: { /* putc */
		unsigned char c = (unsigned char)xrand();
		int rc = seq_buf_putc_c_ref(&cs, c);
		int rr = seq_buf_putc(&rs, c);
		check(rc == rr, "putc: return value");
		break;
	}
	case 2: { /* putmem */
		unsigned char mem[16];
		unsigned len = xrand() % 17, i;
		for (i = 0; i < len; i++) mem[i] = (unsigned char)xrand();
		int rc = seq_buf_putmem_c_ref(&cs, mem, len);
		int rr = seq_buf_putmem(&rs, mem, len);
		check(rc == rr, "putmem: return value");
		break;
	}
	case 3: { /* putmem_hex */
		unsigned char mem[20];
		unsigned len = xrand() % 21, i;
		for (i = 0; i < len; i++) mem[i] = (unsigned char)xrand();
		int rc = seq_buf_putmem_hex_c_ref(&cs, mem, len);
		int rr = seq_buf_putmem_hex(&rs, mem, len);
		check(rc == rr, "putmem_hex: return value");
		if (getenv("SEQ_BUF_DEBUG_HEX")) {
			fprintf(stderr, "  mem(len=%u):", len);
			for (i = 0; i < len; i++) fprintf(stderr, " %02x", mem[i]);
			fprintf(stderr, "\n");
		}
		break;
	}
	case 4: { /* do_printk */
		const char *c1 = printk_capture_reset();
		seq_buf_do_printk_c_ref(&cs, "");
		char cap_c[4096]; strncpy(cap_c, c1, sizeof(cap_c) - 1); cap_c[sizeof(cap_c)-1] = 0;
		const char *c2 = printk_capture_reset();
		seq_buf_do_printk(&rs, "");
		check(strcmp(cap_c, c2) == 0, "do_printk: printk output matches");
		break;
	}
	case 5: { /* to_user */
		unsigned char *fake = test_copy_to_user_fake_buf();
		size_t fakesz = test_copy_to_user_fake_buf_size();
		size_t start = xrand() % (bufsz + 2);
		int cnt = xrand() % (bufsz + 4);
		/* Sometimes target the real fake buffer (success path),
		 * sometimes an address outside it (failure path) -- both
		 * arms see the identical simulated primitive either way. */
		void *to = (xrand() & 1) ? (void *)fake : (void *)((char *)fake + fakesz + 0x1000);
		int rc = seq_buf_to_user_c_ref(&cs, to, start, cnt);
		int rr = seq_buf_to_user(&rs, to, start, cnt);
		check(rc == rr, "to_user: return value");
		break;
	}
	}

	check(cs.len == rs.len, "seq_buf.len matches after the op");
	check(seq_buf_overflowed(&cs) == seq_buf_overflowed(&rs), "overflow state matches");
	if (memcmp(cbuf, rbuf, bufsz) != 0) {
		static int dumped;
		checks++; fails++;
		fprintf(stderr, "MISMATCH: buffer contents match byte-for-byte\n");
		if (dumped++ < 5) {
			unsigned i;
			fprintf(stderr, "  case=%d bufsz=%u cs.len=%zu rs.len=%zu\n", case_idx, bufsz, cs.len, rs.len);
			fprintf(stderr, "  c:"); for (i = 0; i < bufsz; i++) fprintf(stderr, " %02x", (unsigned char)cbuf[i]); fprintf(stderr, "\n");
			fprintf(stderr, "  r:"); for (i = 0; i < bufsz; i++) fprintf(stderr, " %02x", (unsigned char)rbuf[i]); fprintf(stderr, "\n");
		}
	} else {
		check(1, "buffer contents match byte-for-byte");
	}
}

int main(int argc, char **argv)
{
	long n = argc > 1 ? atol(argv[1]) : 20000;
	rng_state = argc > 2 ? (uint32_t)atol(argv[2]) : 0xC0FFEE;
	if (!rng_state) rng_state = 1;

	if (getenv("SEQ_BUF_PROVE_CAN_FAIL")) {
		/* Poison: compare the C reference against ITSELF via a
		 * deliberately wrong expectation, to prove this harness can
		 * report a mismatch rather than always passing. */
		struct seq_buf s;
		char buf[8];
		seq_buf_init(&s, buf, sizeof(buf));
		int rc = seq_buf_puts_c_ref(&s, "ok");
		check(rc == 12345, "POISON: deliberately wrong expectation");
		return fails ? 1 : 0;
	}

	for (long i = 0; i < n; i++)
		one_scenario();

	printf("seq_buf: %ld scenarios, %u checks, %u fails\n", n, checks, fails);
	return fails ? 1 : 0;
}
