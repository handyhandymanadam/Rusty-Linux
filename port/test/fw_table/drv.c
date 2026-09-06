// SPDX-License-Identifier: GPL-2.0-only
/*
 * port/test/fw_table/drv.c -- the userspace differential for lib/fw_table.c.
 *
 * WHAT IS COMPARED
 *
 * This is a walker over attacker- and firmware-controlled length fields, so
 * the return value is the least interesting thing about it. Every run
 * compares four things:
 *
 *   1. the return value;
 *   2. every `proc[i].count`, written back through the CALLER's array;
 *   3. the exact sequence of handler invocations -- which proc entry, the
 *      byte OFFSET of the entry within the table, and the `end` argument as
 *      an offset, so the two arms' different buffer addresses are comparable;
 *   4. THE DIAGNOSTIC TEXT. `pr_err`/`pr_warn` go through a `_printk` this
 *      file defines, and both arms' formatted output is compared byte for
 *      byte. That is not decoration: the C passes `proc->id` -- the FIRST
 *      handler's id -- to both diagnostics rather than the id of the entry
 *      that actually failed. A port that "fixed" that would pass every
 *      other check here. (An earlier version of this comment also claimed
 *      the `%4.4s` was load-bearing over a non-NUL-terminated signature.
 *      It is not: `run_shape()` always passes a zeroed 8-byte buffer, and
 *      `%.4s` would not read past four bytes in any case. The precision is
 *      still compared -- sabotage.sh's `%3.3s` slip is caught -- but the
 *      reason given for it was wrong. Adversarial review, 2026-09-05.)
 *
 * AND ONE THING THAT IS NOT A COMPARISON
 *
 * `stage_guard_page()` places the table so its last declared byte is flush
 * against a PROT_NONE page. Neither arm may read past `table_end`, and a
 * differential structurally cannot notice that they both did -- they would
 * read the same bytes and agree. This is the same instrument
 * port/test/lib/'s base64 poison buffer and port/test/memneq/'s guard-page
 * stage are, pointed at the one property that matters for a table walker.
 *
 * WHAT IT DOES NOT COVER, stated rather than left to be discovered:
 *
 *   - The wrap. `table_header + table_len` and `entry.hdr + entry_len` wrap
 *     in the C and are `wrapping_add` in the port, but reaching a wrap needs
 *     a table placed near the top of the address space. Nothing here can
 *     allocate one. The port's arithmetic is documented site by site and
 *     unverified by this harness.
 *   - Byte order. The CDAT paths convert through `le16_to_cpu`/`le32_to_cpu`
 *     and every other family reads native; on x86-64 those are the same
 *     instruction. logs/floor.md RAISE 5 wants a big-endian run and this
 *     harness has not had one.
 *   - Section placement. `__init` has no meaning in a userspace program.
 *     run.sh checks it with objdump on both objects instead.
 */

#include <linux/acpi.h>
#include <linux/errno.h>
#include <linux/fw_table.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* --------------------------------------------------------------------- */
/* The two arms.                                                          */
/* --------------------------------------------------------------------- */

int c_acpi_parse_entries_array(char *id, unsigned long table_size,
			       union fw_table_header *table_header,
			       unsigned long max_length,
			       struct acpi_subtable_proc *proc,
			       int proc_num, unsigned int max_entries);
int c_cdat_table_parse(enum acpi_cdat_type type,
		       acpi_tbl_entry_handler_arg handler_arg, void *arg,
		       struct acpi_table_cdat *table_header,
		       unsigned long length);

/* --------------------------------------------------------------------- */
/* Bookkeeping.                                                           */
/* --------------------------------------------------------------------- */

#define MAXPROC 4
#define MAXCALL 512
#define LOGSZ   4096

struct callrec {
	int proc_idx;
	unsigned long hdr_off;		/* from the table base */
	unsigned long end_off;		/* from the table base */
};

struct arm {
	const char *name;
	unsigned char *table;		/* this arm's copy of the bytes */
	unsigned long table_len;
	struct acpi_subtable_proc proc[MAXPROC];
	struct callrec call[MAXCALL];
	int ncall;
	int overflow;
	char log[LOGSZ];
	int logused;
	int ret;
};

static struct arm A_REF = { .name = "ref" };
static struct arm A_RS  = { .name = "rs" };

/* Which arm is running: _printk and the handlers need to know. */
static struct arm *cur;

static unsigned long mismatches;
static unsigned long checks;
static unsigned long runs;

/* Volume counters. STATUS.md standing guard 9: a clean result with an
 * implausible volume has not checked your work. In particular the
 * diagnostic-text comparison is worth nothing if no diagnostic ever fired,
 * and "0 mismatches" looks identical either way -- so the number of runs
 * that produced one is printed rather than assumed. */
static unsigned long total_handler_calls;
static unsigned long total_diag_runs;
static unsigned long total_diag_bytes;

static int prove_can_fail;

static unsigned long stage_checks_at_start;
static unsigned long stage_runs_at_start;

static void stage_begin(const char *label)
{
	stage_checks_at_start = checks;
	stage_runs_at_start = runs;
	printf("  %-18s ", label);
	fflush(stdout);
}

static void stage_end(void)
{
	printf("runs %-8lu comparisons %-9lu %s\n",
	       runs - stage_runs_at_start, checks - stage_checks_at_start,
	       mismatches ? "*** MISMATCH ***" : "ok");
}

/* The leading newline is load-bearing: stage_begin() leaves a partial line,
 * and run.sh's prove-can-fail gate greps for a line-anchored MISMATCH. This
 * exact defect was found by adversarial review in port/test/interval_tree/
 * and is not repeated here. */
#define FAIL(fmt, ...)							\
	do {								\
		if (mismatches++ < 20)					\
			printf("\nMISMATCH: " fmt "\n", ##__VA_ARGS__);	\
	} while (0)

/* --------------------------------------------------------------------- */
/* printk capture -- shared by both arms, one at a time.                   */
/* --------------------------------------------------------------------- */

int _printk(const char *fmt, ...)
{
	va_list ap;
	int n;

	if (!cur)
		return 0;
	va_start(ap, fmt);
	n = vsnprintf(cur->log + cur->logused,
		      (size_t)(LOGSZ - cur->logused), fmt, ap);
	va_end(ap);
	if (n > 0) {
		cur->logused += n;
		if (cur->logused > LOGSZ - 1)
			cur->logused = LOGSZ - 1;
	}
	return n;
}

/* --------------------------------------------------------------------- */
/* The handlers. One body, two symbols, so each arm logs separately.       */
/* --------------------------------------------------------------------- */

/* What every handler in a run returns, so a failing handler can be a
 * corpus axis rather than a separate stage. */
static int handler_verdict;

static void record(union acpi_subtable_headers *hdr, unsigned long end,
		   int which)
{
	struct callrec *c;

	if (cur->ncall >= MAXCALL) {
		cur->overflow = 1;
		return;
	}
	total_handler_calls++;
	c = &cur->call[cur->ncall++];
	c->proc_idx = which;
	c->hdr_off = (unsigned long)hdr - (unsigned long)cur->table;
	c->end_off = end - (unsigned long)cur->table;
}

/* `arg` carries the proc index so one handler body serves all four slots. */
static int handler_plain(union acpi_subtable_headers *hdr, const unsigned long end)
{
	record(hdr, end, -1);
	return handler_verdict;
}

static int handler_with_arg(union acpi_subtable_headers *hdr, void *arg,
			    const unsigned long end)
{
	record(hdr, end, (int)(long)arg);
	return handler_verdict;
}

/* --------------------------------------------------------------------- */
/* RNG.                                                                   */
/* --------------------------------------------------------------------- */

static unsigned long long rng_state = 0x9E3779B97F4A7C15ULL;

static unsigned long long rnd(void)
{
	unsigned long long x = rng_state;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	rng_state = x;
	return x * 0x2545F4914F6CDD1DULL;
}

static unsigned long rnd_below(unsigned long n)
{
	return n ? (unsigned long)(rnd() % n) : 0;
}

/* --------------------------------------------------------------------- */
/* The corpus: a table header followed by a run of subtables.              */
/* --------------------------------------------------------------------- */

#define BUFSZ 65536

static unsigned char buf_ref[BUFSZ];
static unsigned char buf_rs[BUFSZ];

/* The five signatures acpi_get_subtable_type() recognises, plus one it does
 * not (which is what selects ACPI_SUBTABLE_COMMON) and two malformed short
 * ones that exercise strncmp's stop-at-NUL. */
static const char *const SIGS[] = {
	ACPI_SIG_HMAT, ACPI_SIG_PRMT, ACPI_SIG_CEDT, ACPI_SIG_CDAT,
	/* Three bytes of a real signature and a fourth that differs. Without
	 * these, a strncmp shortened to three bytes is invisible: every
	 * recognised signature already differs by byte 1, so three bytes are
	 * enough to tell them apart and the fourth never decides anything.
	 * Found by sabotage.sh, which is what it is for. */
	"HMAX", "PRMX", "CEDX", "CDAX",
	"MADT", "SRAT", "HM", "H", "",
};
#define NSIGS ((int)(sizeof(SIGS) / sizeof(SIGS[0])))

struct shape {
	const char *sig;
	unsigned long table_size;	/* offset to the first subtable */
	unsigned long declared_len;	/* what the table header claims */
	unsigned long max_length;
	int proc_num;
	int proc_id[MAXPROC];
	int use_arg[MAXPROC];		/* handler_arg vs handler vs neither */
	unsigned int max_entries;
	int verdict;			/* what the handlers return */
	unsigned long nbytes;		/* how much of the buffer is filled */
};

/* Write the family's table header into `p` with a declared length. CDAT
 * headers are 16 bytes and little-endian; everything else uses the 36-byte
 * ACPI header with a native-endian length. */
static void put_table_header(unsigned char *p, const char *sig,
			     unsigned long declared_len)
{
	if (strncmp(sig, ACPI_SIG_CDAT, 4) == 0) {
		struct acpi_table_cdat h;

		memset(&h, 0, sizeof(h));
		h.length = cpu_to_le32((u32)declared_len);
		h.revision = 1;
		memcpy(p, &h, sizeof(h));
	} else {
		struct acpi_table_header h;

		memset(&h, 0, sizeof(h));
		memcpy(h.signature, sig, strnlen(sig, 4));
		h.length = (u32)declared_len;
		h.revision = 1;
		memcpy(p, &h, sizeof(h));
	}
}

/* Lay a subtable header of the family `sig` selects at `p`, with `type` and
 * `len`. Deliberately writes through the raw bytes at the offsets the family
 * uses rather than through a struct, so the generator cannot inherit a
 * layout mistake from the port. */
static void put_subtable(unsigned char *p, const char *sig,
			 unsigned long type, unsigned long len)
{
	if (strncmp(sig, ACPI_SIG_HMAT, 4) == 0) {
		/* HMAT is the only family with a 16-bit type and a 32-bit
		 * length, so it is the only one where reading either at the
		 * wrong width is observable -- and only for values that do
		 * not fit in the narrower one. The generator produces those
		 * deliberately; a corpus of small types and small lengths
		 * cannot tell a u16 read from a u8 one. */
		p[0] = (unsigned char)(type & 0xff);
		p[1] = (unsigned char)((type >> 8) & 0xff);
		p[2] = 0;
		p[3] = 0;
		p[4] = (unsigned char)(len & 0xff);
		p[5] = (unsigned char)((len >> 8) & 0xff);
		p[6] = (unsigned char)((len >> 16) & 0xff);
		p[7] = (unsigned char)((len >> 24) & 0xff);
	} else if (strncmp(sig, ACPI_SIG_PRMT, 4) == 0) {
		/* PRMT's type is a hard 0 in the C -- the revision at offset
		 * 0 is NOT it. Writing a non-zero revision is what makes a
		 * port that returns it instead observable. */
		p[0] = (unsigned char)(type & 0xff);
		p[1] = (unsigned char)((type >> 8) & 0xff);
		p[2] = (unsigned char)(len & 0xff);
		p[3] = (unsigned char)((len >> 8) & 0xff);
	} else if (strncmp(sig, ACPI_SIG_CEDT, 4) == 0 ||
		   strncmp(sig, ACPI_SIG_CDAT, 4) == 0) {
		/* Same byte layout; CDAT reads its length little-endian and
		 * CEDT natively, which is the same thing on this host. */
		p[0] = (unsigned char)(type & 0xff);
		p[1] = 0;
		p[2] = (unsigned char)(len & 0xff);
		p[3] = (unsigned char)((len >> 8) & 0xff);
	} else {				/* ACPI_SUBTABLE_COMMON */
		p[0] = (unsigned char)(type & 0xff);
		p[1] = (unsigned char)(len & 0xff);
	}
}

static unsigned long family_header_size(const char *sig)
{
	if (strncmp(sig, ACPI_SIG_HMAT, 4) == 0)
		return 8;
	if (strncmp(sig, ACPI_SIG_PRMT, 4) == 0)
		return 4;
	if (strncmp(sig, ACPI_SIG_CEDT, 4) == 0 ||
	    strncmp(sig, ACPI_SIG_CDAT, 4) == 0)
		return 4;
	return 2;
}

static unsigned long root_header_size(const char *sig)
{
	return strncmp(sig, ACPI_SIG_CDAT, 4) == 0
		? sizeof(struct acpi_table_cdat)
		: sizeof(struct acpi_table_header);
}

/* --------------------------------------------------------------------- */
/* Running one shape through both arms.                                    */
/* --------------------------------------------------------------------- */

static void arm_setup(struct arm *a, unsigned char *buf,
		      const struct shape *s, int argbase)
{
	int i;

	a->table = buf;
	a->table_len = s->nbytes;
	a->ncall = 0;
	a->overflow = 0;
	a->logused = 0;
	memset(a->log, 0, sizeof(a->log));
	memset(a->proc, 0, sizeof(a->proc));

	for (i = 0; i < s->proc_num; i++) {
		a->proc[i].id = s->proc_id[i];
		switch (s->use_arg[i]) {
		case 0:
			a->proc[i].handler = handler_plain;
			break;
		case 1:
			a->proc[i].handler_arg = handler_with_arg;
			a->proc[i].arg = (void *)(long)(argbase + i);
			break;
		case 3:
			/* BOTH. call_handler() prefers `handler`, and nothing
			 * in this corpus set both until sabotage.sh showed
			 * that swapping the preference was invisible. */
			a->proc[i].handler = handler_plain;
			a->proc[i].handler_arg = handler_with_arg;
			a->proc[i].arg = (void *)(long)(argbase + i);
			break;
		default:
			/* Neither -- call_handler() must return -EINVAL. */
			break;
		}
	}
}

static void run_shape(const struct shape *s, const char *where,
		      unsigned long iter)
{
	char idbuf[8];
	int i;

	runs++;
	handler_verdict = s->verdict;

	memcpy(buf_rs, buf_ref, s->nbytes);
	if (prove_can_fail && s->nbytes > 0) {
		/* THE ARRANGEMENT PROVES ITSELF. One byte of the Rust arm's
		 * table differs, so the two must disagree somewhere. */
		buf_rs[s->nbytes - 1] ^= 0x01;
		if (s->nbytes > root_header_size(s->sig))
			buf_rs[root_header_size(s->sig)] ^= 0x01;
	}

	memset(idbuf, 0, sizeof(idbuf));
	memcpy(idbuf, s->sig, strlen(s->sig));

	arm_setup(&A_REF, buf_ref, s, 100);
	arm_setup(&A_RS, buf_rs, s, 100);

	cur = &A_REF;
	A_REF.ret = c_acpi_parse_entries_array(idbuf, s->table_size,
					       (union fw_table_header *)buf_ref,
					       s->max_length, A_REF.proc,
					       s->proc_num, s->max_entries);
	cur = &A_RS;
	A_RS.ret = acpi_parse_entries_array(idbuf, s->table_size,
					    (union fw_table_header *)buf_rs,
					    s->max_length, A_RS.proc,
					    s->proc_num, s->max_entries);
	cur = NULL;
	checks++;

	if (A_REF.ret != A_RS.ret) {
		FAIL("%s iter %lu: [%s] return ref=%d rs=%d "
		     "(table_size=%lu max_length=%lu proc_num=%d max_entries=%u)",
		     where, iter, idbuf, A_REF.ret, A_RS.ret,
		     s->table_size, s->max_length, s->proc_num, s->max_entries);
		return;
	}
	for (i = 0; i < s->proc_num; i++) {
		if (A_REF.proc[i].count != A_RS.proc[i].count) {
			FAIL("%s iter %lu: [%s] proc[%d].count ref=%d rs=%d",
			     where, iter, idbuf, i,
			     A_REF.proc[i].count, A_RS.proc[i].count);
			return;
		}
	}
	if (A_REF.overflow || A_RS.overflow) {
		FAIL("%s iter %lu: [%s] handler-call log overflowed "
		     "(ref=%d rs=%d) -- the shape is too big for MAXCALL",
		     where, iter, idbuf, A_REF.overflow, A_RS.overflow);
		return;
	}
	if (A_REF.ncall != A_RS.ncall) {
		FAIL("%s iter %lu: [%s] handler called %d times in ref, %d in rs",
		     where, iter, idbuf, A_REF.ncall, A_RS.ncall);
		return;
	}
	for (i = 0; i < A_REF.ncall; i++) {
		const struct callrec *c = &A_REF.call[i], *r = &A_RS.call[i];

		if (c->proc_idx != r->proc_idx || c->hdr_off != r->hdr_off ||
		    c->end_off != r->end_off) {
			FAIL("%s iter %lu: [%s] handler call %d differs\n"
			     "    ref proc=%d hdr@%lu end@%lu\n"
			     "    rs  proc=%d hdr@%lu end@%lu",
			     where, iter, idbuf, i,
			     c->proc_idx, c->hdr_off, c->end_off,
			     r->proc_idx, r->hdr_off, r->end_off);
			return;
		}
	}
	if (A_REF.logused) {
		total_diag_runs++;
		total_diag_bytes += (unsigned long)A_REF.logused;
	}
	if (strcmp(A_REF.log, A_RS.log) != 0) {
		FAIL("%s iter %lu: [%s] diagnostic text differs\n"
		     "    ref %s\n"
		     "    rs  %s",
		     where, iter, idbuf, A_REF.log, A_RS.log);
		return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 1 -- random tables.                                               */
/* --------------------------------------------------------------------- */

static void fill_random_table(struct shape *s, int allow_zero_len)
{
	unsigned long off, hdrsz;
	int n;

	s->sig = SIGS[rnd_below(NSIGS)];
	hdrsz = family_header_size(s->sig);
	s->table_size = root_header_size(s->sig);

	/* Occasionally start the entries somewhere other than right after
	 * the root header -- table_size is a caller-supplied offset and the
	 * C never checks it against the table's own length. */
	if (rnd_below(8) == 0)
		s->table_size += rnd_below(16);

	memset(buf_ref, 0, BUFSZ);

	off = s->table_size;
	n = (int)rnd_below(24) + 1;
	while (n-- > 0 && off + 64 < BUFSZ - 64) {
		unsigned long type, len;

		/* Mostly small types, sometimes one that needs more than
		 * eight bits -- only HMAT has a 16-bit type field, and only
		 * such a value distinguishes reading it as u16 from u8. */
		type = rnd_below(8) == 0 ? 0x100 + rnd_below(0x300)
					 : rnd_below(6);

		if (allow_zero_len && rnd_below(20) == 0)
			len = 0;
		else if (rnd_below(24) == 0)
			/* Wider than 16 bits. Only HMAT stores a 32-bit
			 * length; the walk stops on it either way, but a
			 * port that truncated it to u16 would carry on. */
			len = 0x10000 + rnd_below(0x1000);
		else
			len = hdrsz + rnd_below(24);

		put_subtable(buf_ref + off, s->sig, type, len);
		off += len ? len : hdrsz;
		if (off + 64 >= BUFSZ - 64)
			break;
	}
	s->nbytes = off + 64;
	if (s->nbytes > BUFSZ)
		s->nbytes = BUFSZ;

	/* The declared length is usually honest, sometimes short, sometimes
	 * longer than what was written -- all three are things firmware
	 * really does. */
	switch (rnd_below(4)) {
	case 0:  s->declared_len = off; break;
	case 1:  s->declared_len = off / 2; break;
	case 2:  s->declared_len = s->nbytes; break;
	default: s->declared_len = off + rnd_below(32); break;
	}
	if (s->declared_len > s->nbytes)
		s->declared_len = s->nbytes;

	put_table_header(buf_ref, s->sig, s->declared_len);

	s->max_length = rnd_below(4) == 0 ? rnd_below(s->declared_len + 8) : 0;
	s->proc_num = (int)rnd_below(MAXPROC) + 1;
	for (int i = 0; i < s->proc_num; i++) {
		/* Mostly ids that exist in the table, sometimes ones that do
		 * not, and sometimes NEGATIVE -- which the C sign-extends to
		 * a huge unsigned long before comparing, so it can never
		 * match. That promotion is one of the two the port documents. */
		if (rnd_below(10) == 0)
			s->proc_id[i] = -(int)rnd_below(4) - 1;
		else
			s->proc_id[i] = (int)rnd_below(8);
		/* 0 = handler, 1 = handler_arg, 2 = neither, 3 = both. */
		if (rnd_below(16) == 0)
			s->use_arg[i] = 2;
		else if (rnd_below(6) == 0)
			s->use_arg[i] = 3;
		else
			s->use_arg[i] = (int)rnd_below(2);
	}
	s->max_entries = rnd_below(3) == 0 ? (unsigned int)rnd_below(6) : 0;
	s->verdict = rnd_below(12) == 0 ? -1 : 0;
}

static void stage_random(unsigned long iters, int allow_zero_len,
			 const char *label)
{
	struct shape s;
	unsigned long i;

	for (i = 0; i < iters; i++) {
		memset(&s, 0, sizeof(s));
		fill_random_table(&s, allow_zero_len);
		run_shape(&s, label, i);
		if (mismatches)
			return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 2 -- the cases random input does not reach.                       */
/* --------------------------------------------------------------------- */

static void directed(const char *what, struct shape *s)
{
	run_shape(s, what, 0);
}

static void stage_directed(void)
{
	struct shape s;
	unsigned long hdrsz;
	int i;

	/* --- an entry with length 0: the infinite-loop guard and the only
	 * pr_err in the file. --- */
	for (i = 0; i < NSIGS; i++) {
		memset(&s, 0, sizeof(s));
		s.sig = SIGS[i];
		hdrsz = family_header_size(s.sig);
		s.table_size = root_header_size(s.sig);
		memset(buf_ref, 0, BUFSZ);
		put_subtable(buf_ref + s.table_size, s.sig, 1, hdrsz);
		put_subtable(buf_ref + s.table_size + hdrsz, s.sig, 1, 0);
		s.nbytes = s.table_size + 4 * hdrsz + 32;
		s.declared_len = s.nbytes;
		put_table_header(buf_ref, s.sig, s.declared_len);
		s.proc_num = 1;
		s.proc_id[0] = 1;
		s.use_arg[0] = 0;
		directed("directed/zero-len", &s);
	}

	/* --- max_entries: the unsigned comparisons, and the pr_warn. The
	 * warning needs count > max_entries, which needs entries to keep
	 * being COUNTED after they stop being handled. --- */
	for (unsigned int me = 0; me <= 4; me++) {
		memset(&s, 0, sizeof(s));
		s.sig = ACPI_SIG_CEDT;
		hdrsz = family_header_size(s.sig);
		s.table_size = root_header_size(s.sig);
		memset(buf_ref, 0, BUFSZ);
		for (i = 0; i < 6; i++)
			put_subtable(buf_ref + s.table_size + (unsigned long)i * hdrsz,
				     s.sig, 2, hdrsz);
		s.nbytes = s.table_size + 6 * hdrsz + 32;
		s.declared_len = s.table_size + 6 * hdrsz;
		put_table_header(buf_ref, s.sig, s.declared_len);
		s.proc_num = 1;
		s.proc_id[0] = 2;
		s.use_arg[0] = 0;
		s.max_entries = me;
		directed("directed/max-entries", &s);
	}

	/* --- max_entries with the SIGN BIT SET. fw_table.c:180 and :203
	 * compare an `int count` against an `unsigned int max_entries`, so C
	 * converts the int and the comparison is UNSIGNED. With max_entries
	 * below 6 -- which is all the corpus above ever produced -- a port
	 * that compared them as signed gives identical answers, and both
	 * mutations passed the entire suite. Found by adversarial review,
	 * 2026-09-05, which is exactly the case sabotage.sh could not reach
	 * and now can.
	 *
	 * Above 2^31 the two readings diverge: `count < (unsigned)max_entries`
	 * stays true for every plausible count, while `count < (int)max_entries`
	 * is comparing against a NEGATIVE number and is false at once. --- */
	{
		static const unsigned int BIG[] = {
			0x80000000u, 0x80000001u, 0xffffffffu, 0x7fffffffu,
		};

		for (unsigned int k = 0; k < sizeof(BIG) / sizeof(BIG[0]); k++) {
			memset(&s, 0, sizeof(s));
			s.sig = ACPI_SIG_CEDT;
			hdrsz = family_header_size(s.sig);
			s.table_size = root_header_size(s.sig);
			memset(buf_ref, 0, BUFSZ);
			for (i = 0; i < 6; i++)
				put_subtable(buf_ref + s.table_size +
					     (unsigned long)i * hdrsz,
					     s.sig, 2, hdrsz);
			s.nbytes = s.table_size + 6 * hdrsz + 32;
			s.declared_len = s.table_size + 6 * hdrsz;
			put_table_header(buf_ref, s.sig, s.declared_len);
			s.proc_num = 1;
			s.proc_id[0] = 2;
			s.use_arg[0] = 0;
			s.max_entries = BIG[k];
			directed("directed/max-entries-big", &s);
		}
	}

	/* --- a proc entry with NEITHER handler set: call_handler() returns
	 * -EINVAL and the walk stops. --- */
	memset(&s, 0, sizeof(s));
	s.sig = ACPI_SIG_HMAT;
	hdrsz = family_header_size(s.sig);
	s.table_size = root_header_size(s.sig);
	memset(buf_ref, 0, BUFSZ);
	put_subtable(buf_ref + s.table_size, s.sig, 3, hdrsz);
	s.nbytes = s.table_size + 4 * hdrsz + 32;
	s.declared_len = s.nbytes;
	put_table_header(buf_ref, s.sig, s.declared_len);
	s.proc_num = 1;
	s.proc_id[0] = 3;
	s.use_arg[0] = 2;			/* neither handler */
	directed("directed/no-handler", &s);

	/* --- a handler that fails: the -EINVAL early return, with the
	 * proc[i].count NOT incremented for the failing entry. --- */
	memset(&s, 0, sizeof(s));
	s.sig = ACPI_SIG_CDAT;
	hdrsz = family_header_size(s.sig);
	s.table_size = root_header_size(s.sig);
	memset(buf_ref, 0, BUFSZ);
	for (i = 0; i < 4; i++)
		put_subtable(buf_ref + s.table_size + (unsigned long)i * hdrsz,
			     s.sig, 0, hdrsz);
	s.nbytes = s.table_size + 4 * hdrsz + 32;
	s.declared_len = s.nbytes;
	put_table_header(buf_ref, s.sig, s.declared_len);
	s.proc_num = 1;
	s.proc_id[0] = 0;
	s.use_arg[0] = 1;
	s.verdict = -1;
	directed("directed/handler-fails", &s);

	/* --- an empty table: declared length leaves no room for one entry,
	 * so the loop body never runs and the return is 0. --- */
	for (i = 0; i < NSIGS; i++) {
		memset(&s, 0, sizeof(s));
		s.sig = SIGS[i];
		s.table_size = root_header_size(s.sig);
		memset(buf_ref, 0, BUFSZ);
		s.nbytes = s.table_size + 64;
		s.declared_len = s.table_size;
		put_table_header(buf_ref, s.sig, s.declared_len);
		s.proc_num = 1;
		s.proc_id[0] = 0;
		s.use_arg[0] = 0;
		directed("directed/empty", &s);
	}

	/* --- max_length truncating the table's own declared length, and
	 * max_length longer than it (which must be ignored). --- */
	for (int k = 0; k < 6; k++) {
		memset(&s, 0, sizeof(s));
		s.sig = ACPI_SIG_PRMT;
		hdrsz = family_header_size(s.sig);
		s.table_size = root_header_size(s.sig);
		memset(buf_ref, 0, BUFSZ);
		for (i = 0; i < 5; i++)
			put_subtable(buf_ref + s.table_size + (unsigned long)i * hdrsz,
				     s.sig, 0, hdrsz);
		s.nbytes = s.table_size + 5 * hdrsz + 32;
		s.declared_len = s.table_size + 5 * hdrsz;
		put_table_header(buf_ref, s.sig, s.declared_len);
		s.proc_num = 1;
		s.proc_id[0] = 0;	/* PRMT's type is always 0 */
		s.use_arg[0] = 0;
		s.max_length = s.table_size + (unsigned long)k * hdrsz;
		directed("directed/max-length", &s);
	}
}

/* --------------------------------------------------------------------- */
/* Stage 3 -- neither arm may read past table_end.                         */
/* --------------------------------------------------------------------- */

static unsigned char *guard_alloc(unsigned long len, unsigned char **base,
				  unsigned long *maplen)
{
	long pg = sysconf(_SC_PAGESIZE);
	unsigned long pages = ((len + (unsigned long)pg - 1) / (unsigned long)pg) + 1;
	unsigned char *p;

	*maplen = pages * (unsigned long)pg;
	p = mmap(NULL, *maplen, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return NULL;
	/* Last page unreadable. */
	if (mprotect(p + (pages - 1) * (unsigned long)pg, (unsigned long)pg,
		     PROT_NONE) != 0)
		return NULL;
	*base = p;
	/* Place the table so its last byte is flush against the guard. */
	return p + (pages - 1) * (unsigned long)pg - len;
}

static void stage_guard_page(unsigned long iters, const char *label)
{
	unsigned long i;

	for (i = 0; i < iters; i++) {
		struct shape s;
		unsigned char *base_a = NULL, *base_b = NULL;
		unsigned char *ta, *tb;
		unsigned long len, maplen_a = 0, maplen_b = 0;
		char idbuf[8];
		int k;

		memset(&s, 0, sizeof(s));
		fill_random_table(&s, 1);
		/* The declared length IS the allocation: anything the walker
		 * reads at or past table_end faults. */
		len = s.declared_len;
		if (len < root_header_size(s.sig) + 8)
			continue;

		ta = guard_alloc(len, &base_a, &maplen_a);
		tb = guard_alloc(len, &base_b, &maplen_b);
		if (!ta || !tb) {
			FAIL("%s iter %lu: guard-page allocation failed", label, i);
			return;
		}
		memcpy(ta, buf_ref, len);
		memcpy(tb, buf_ref, len);
		if (prove_can_fail)
			tb[len - 1] ^= 0x01;

		memset(idbuf, 0, sizeof(idbuf));
		memcpy(idbuf, s.sig, strlen(s.sig));

		A_REF.table = ta; A_RS.table = tb;
		A_REF.ncall = A_RS.ncall = 0;
		A_REF.overflow = A_RS.overflow = 0;
		A_REF.logused = A_RS.logused = 0;
		A_REF.log[0] = A_RS.log[0] = 0;
		memset(A_REF.proc, 0, sizeof(A_REF.proc));
		memset(A_RS.proc, 0, sizeof(A_RS.proc));
		for (k = 0; k < s.proc_num; k++) {
			A_REF.proc[k].id = A_RS.proc[k].id = s.proc_id[k];
			A_REF.proc[k].handler = A_RS.proc[k].handler = handler_plain;
		}
		handler_verdict = 0;
		runs++;
		checks++;

		cur = &A_REF;
		A_REF.ret = c_acpi_parse_entries_array(idbuf, s.table_size,
						       (union fw_table_header *)ta,
						       0, A_REF.proc, s.proc_num, 0);
		cur = &A_RS;
		A_RS.ret = acpi_parse_entries_array(idbuf, s.table_size,
						    (union fw_table_header *)tb,
						    0, A_RS.proc, s.proc_num, 0);
		cur = NULL;

		/* Compare everything, not just the return value. The stage
		 * exists for the fault, but there is no reason to throw away
		 * the comparison while it is here -- adversarial review,
		 * 2026-09-05. */
		if (A_REF.ret != A_RS.ret) {
			FAIL("%s iter %lu: [%s] guard-page return ref=%d rs=%d",
			     label, i, idbuf, A_REF.ret, A_RS.ret);
		} else if (A_REF.ncall != A_RS.ncall) {
			FAIL("%s iter %lu: [%s] guard-page handler called %d/%d",
			     label, i, idbuf, A_REF.ncall, A_RS.ncall);
		} else if (strcmp(A_REF.log, A_RS.log) != 0) {
			FAIL("%s iter %lu: [%s] guard-page diagnostic differs\n"
			     "    ref %s\n    rs  %s",
			     label, i, idbuf, A_REF.log, A_RS.log);
		} else {
			for (k = 0; k < s.proc_num; k++)
				if (A_REF.proc[k].count != A_RS.proc[k].count) {
					FAIL("%s iter %lu: [%s] guard-page "
					     "proc[%d].count ref=%d rs=%d",
					     label, i, idbuf, k,
					     A_REF.proc[k].count,
					     A_RS.proc[k].count);
					break;
				}
			for (k = 0; k < A_REF.ncall && !mismatches; k++)
				if (A_REF.call[k].hdr_off != A_RS.call[k].hdr_off ||
				    A_REF.call[k].end_off != A_RS.call[k].end_off) {
					FAIL("%s iter %lu: [%s] guard-page call "
					     "%d differs", label, i, idbuf, k);
					break;
				}
		}

		munmap(base_a, maplen_a);
		munmap(base_b, maplen_b);
		if (mismatches)
			return;
	}
}

/* --------------------------------------------------------------------- */
/* Stage 4 -- cdat_table_parse().                                          */
/* --------------------------------------------------------------------- */

static void stage_cdat(unsigned long iters, const char *label)
{
	unsigned long i;

	for (i = 0; i < iters; i++) {
		unsigned long hdrsz = 4, off, root = sizeof(struct acpi_table_cdat);
		unsigned long declared;
		int n, ty;

		memset(buf_ref, 0, BUFSZ);
		off = root;
		n = (int)rnd_below(12) + 1;
		while (n-- > 0 && off + 64 < BUFSZ) {
			unsigned long len = (rnd_below(24) == 0) ? 0
					  : hdrsz + rnd_below(16);
			put_subtable(buf_ref + off, ACPI_SIG_CDAT,
				     rnd_below(7), len);
			off += len ? len : hdrsz;
		}
		declared = off;
		put_table_header(buf_ref, ACPI_SIG_CDAT, declared);
		memcpy(buf_rs, buf_ref, BUFSZ);
		if (prove_can_fail)
			buf_rs[root] ^= 0x01;

		ty = (int)rnd_below(7);
		handler_verdict = rnd_below(12) == 0 ? -1 : 0;

		A_REF.table = buf_ref; A_RS.table = buf_rs;
		A_REF.ncall = A_RS.ncall = 0;
		A_REF.overflow = A_RS.overflow = 0;
		A_REF.logused = A_RS.logused = 0;
		A_REF.log[0] = A_RS.log[0] = 0;
		runs++;
		checks++;

		cur = &A_REF;
		A_REF.ret = c_cdat_table_parse((enum acpi_cdat_type)ty,
					       handler_with_arg, (void *)7L,
					       (struct acpi_table_cdat *)buf_ref,
					       rnd_below(2) ? 0 : declared);
		cur = &A_RS;
		A_RS.ret = cdat_table_parse((enum acpi_cdat_type)ty,
					    handler_with_arg, (void *)7L,
					    (struct acpi_table_cdat *)buf_rs,
					    rnd_below(2) ? 0 : declared);
		cur = NULL;

		if (A_REF.ret != A_RS.ret) {
			FAIL("%s iter %lu: type=%d return ref=%d rs=%d",
			     label, i, ty, A_REF.ret, A_RS.ret);
			return;
		}
		if (A_REF.ncall != A_RS.ncall) {
			FAIL("%s iter %lu: type=%d handler called %d/%d times",
			     label, i, ty, A_REF.ncall, A_RS.ncall);
			return;
		}
		for (int k = 0; k < A_REF.ncall; k++)
			if (A_REF.call[k].hdr_off != A_RS.call[k].hdr_off ||
			    A_REF.call[k].end_off != A_RS.call[k].end_off) {
				FAIL("%s iter %lu: type=%d call %d differs",
				     label, i, ty, k);
				return;
			}
		if (strcmp(A_REF.log, A_RS.log) != 0) {
			FAIL("%s iter %lu: diagnostic differs\n    ref %s\n    rs  %s",
			     label, i, A_REF.log, A_RS.log);
			return;
		}
		if (mismatches)
			return;
	}

	/* The NULL table_header early return, which nothing random reaches. */
	runs++;
	checks++;
	cur = &A_REF;
	A_REF.ret = c_cdat_table_parse(ACPI_CDAT_TYPE_DSMAS, handler_with_arg,
				       NULL, NULL, 0);
	cur = &A_RS;
	A_RS.ret = cdat_table_parse(ACPI_CDAT_TYPE_DSMAS, handler_with_arg,
				    NULL, NULL, 0);
	cur = NULL;
	if (A_REF.ret != A_RS.ret || A_REF.ret != -EINVAL)
		FAIL("%s: NULL table_header ref=%d rs=%d (want %d)",
		     label, A_REF.ret, A_RS.ret, -EINVAL);
}

/* --------------------------------------------------------------------- */
/* Stage 0 -- the part is inspected against the blueprint.                 */
/* --------------------------------------------------------------------- */

#define GEOM_N 48
void rs_geometry(unsigned long *out);

static void geom_check(const char *what, unsigned long got, unsigned long want)
{
	checks++;
	if (got != want) {
		printf("\nGEOMETRY: %s: rust=%lu c=%lu\n", what, got, want);
		mismatches++;
	}
}

static void stage_geometry(void)
{
	unsigned long g[GEOM_N];
	unsigned int i;

	for (i = 0; i < GEOM_N; i++)
		g[i] = ~0UL;
	rs_geometry(g);

	geom_check("sizeof(acpi_table_header)", g[0],
		   sizeof(struct acpi_table_header));
	geom_check("acpi_table_header.signature", g[1],
		   offsetof(struct acpi_table_header, signature));
	geom_check("acpi_table_header.length", g[2],
		   offsetof(struct acpi_table_header, length));
	geom_check("acpi_table_header.revision", g[3],
		   offsetof(struct acpi_table_header, revision));
	geom_check("acpi_table_header.oem_id", g[4],
		   offsetof(struct acpi_table_header, oem_id));
	geom_check("acpi_table_header.asl_compiler_revision", g[5],
		   offsetof(struct acpi_table_header, asl_compiler_revision));

	geom_check("sizeof(acpi_table_cdat)", g[6],
		   sizeof(struct acpi_table_cdat));
	geom_check("acpi_table_cdat.length", g[7],
		   offsetof(struct acpi_table_cdat, length));
	geom_check("acpi_table_cdat.sequence", g[8],
		   offsetof(struct acpi_table_cdat, sequence));

	geom_check("sizeof(acpi_subtable_header)", g[9],
		   sizeof(struct acpi_subtable_header));
	geom_check("acpi_subtable_header.type", g[10],
		   offsetof(struct acpi_subtable_header, type));
	geom_check("acpi_subtable_header.length", g[11],
		   offsetof(struct acpi_subtable_header, length));

	geom_check("sizeof(acpi_hmat_structure)", g[12],
		   sizeof(struct acpi_hmat_structure));
	geom_check("acpi_hmat_structure.type", g[13],
		   offsetof(struct acpi_hmat_structure, type));
	geom_check("acpi_hmat_structure.length", g[14],
		   offsetof(struct acpi_hmat_structure, length));

	geom_check("sizeof(acpi_prmt_module_header)", g[15],
		   sizeof(struct acpi_prmt_module_header));
	geom_check("acpi_prmt_module_header.length", g[16],
		   offsetof(struct acpi_prmt_module_header, length));

	geom_check("sizeof(acpi_cedt_header)", g[17],
		   sizeof(struct acpi_cedt_header));
	geom_check("acpi_cedt_header.type", g[18],
		   offsetof(struct acpi_cedt_header, type));
	geom_check("acpi_cedt_header.length", g[19],
		   offsetof(struct acpi_cedt_header, length));

	geom_check("sizeof(acpi_cdat_header)", g[20],
		   sizeof(struct acpi_cdat_header));
	geom_check("acpi_cdat_header.type", g[21],
		   offsetof(struct acpi_cdat_header, type));
	geom_check("acpi_cdat_header.length", g[22],
		   offsetof(struct acpi_cdat_header, length));

	geom_check("sizeof(union fw_table_header)", g[23],
		   sizeof(union fw_table_header));
	geom_check("sizeof(union acpi_subtable_headers)", g[24],
		   sizeof(union acpi_subtable_headers));

	geom_check("sizeof(acpi_subtable_proc)", g[25],
		   sizeof(struct acpi_subtable_proc));
	geom_check("acpi_subtable_proc.id", g[26],
		   offsetof(struct acpi_subtable_proc, id));
	geom_check("acpi_subtable_proc.handler", g[27],
		   offsetof(struct acpi_subtable_proc, handler));
	geom_check("acpi_subtable_proc.handler_arg", g[28],
		   offsetof(struct acpi_subtable_proc, handler_arg));
	geom_check("acpi_subtable_proc.arg", g[29],
		   offsetof(struct acpi_subtable_proc, arg));
	geom_check("acpi_subtable_proc.count", g[30],
		   offsetof(struct acpi_subtable_proc, count));
	geom_check("alignof(acpi_subtable_proc)", g[31],
		   __alignof__(struct acpi_subtable_proc));
}

/* --------------------------------------------------------------------- */

static unsigned long envnum(const char *name, unsigned long dflt)
{
	const char *v = getenv(name);

	return v ? strtoul(v, NULL, 0) : dflt;
}

int main(void)
{
	unsigned long scale = envnum("FW_TABLE_SCALE", 1);
	unsigned long seed = envnum("FW_TABLE_SEED", 0);

	/* Line-buffered even to a file: a crash must not swallow a verdict
	 * that was already printed, because run.sh's gate reads the printed
	 * verdict rather than the exit code. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	prove_can_fail = getenv("FW_TABLE_PROVE_CAN_FAIL") != NULL;
	if (seed)
		rng_state = seed;

	printf("fw_table differential\n");
	printf("  sizeof(acpi_table_header)      = %zu\n",
	       sizeof(struct acpi_table_header));
	printf("  sizeof(acpi_table_cdat)        = %zu\n",
	       sizeof(struct acpi_table_cdat));
	printf("  sizeof(union fw_table_header)  = %zu\n",
	       sizeof(union fw_table_header));
	printf("  sizeof(acpi_subtable_proc)     = %zu\n",
	       sizeof(struct acpi_subtable_proc));
	printf("  seed = 0x%llx  scale = %lu\n", rng_state, scale);

	stage_geometry();
	if (mismatches) {
		printf("  the two layouts differ; every later stage would be "
		       "comparing nothing. Stopping.\n");
		return 1;
	}

#define STAGE(label, call) \
	do { stage_begin(label); call; stage_end(); } while (0)

	STAGE("random/clean",  stage_random(6000 * scale, 0, "random/clean"));
	STAGE("random/zerolen", stage_random(6000 * scale, 1, "random/zerolen"));
	STAGE("cdat",          stage_cdat(4000 * scale, "cdat"));
	STAGE("guard-page",    stage_guard_page(600 * scale, "guard-page"));
	STAGE("directed",      stage_directed());

	printf("  handler calls          : %lu (both arms combined)\n",
	       total_handler_calls);
	printf("  runs that printed a diagnostic : %lu, %lu bytes compared\n",
	       total_diag_runs, total_diag_bytes);
	printf("  runs        : %lu\n", runs);
	printf("  comparisons : %lu\n", checks);
	printf("  mismatches  : %lu\n", mismatches);
	return mismatches ? 1 : 0;
}
