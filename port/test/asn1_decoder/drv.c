/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/asn1_decoder/drv.c -- differential for lib/asn1_decoder.c.
 *
 * Uses TWO real, production ASN.1 bytecode programs, copied verbatim
 * from the actual compiled kernel build (build-full/crypto/asymmetric_keys/
 * x509_akid.asn1.c and build-full/crypto/rsapubkey.asn1.c -- see the
 * comments above each array below for exact provenance), not a
 * hand-invented grammar -- x509_akid_machine alone exercises MATCH,
 * MATCH_ACT_OR_SKIP, MATCH_JUMP_OR_SKIP, COND_MATCH_OR_SKIP,
 * COND_MATCH_JUMP_OR_SKIP, COND_FAIL, MATCH_ANY, MATCH_ANY_ACT,
 * END_SEQ, END_SEQ_OF, END_SET_OF, ACT, and RETURN -- effectively the
 * whole opcode set except plain (unconditional) MATCH_JUMP and
 * indefinite-length encoding, which rsapubkey_machine's own indefinite-
 * length variants below cover instead.
 *
 * Action callbacks are test-local stubs (not the real x509/rsa action
 * functions, which pull in struct rsa_key/fips_enabled/etc that have
 * nothing to do with the decoder itself) -- each just RECORDS its
 * arguments (index, hdrlen, tag, vlen, and a copy of the value bytes)
 * into a per-arm log, and drv.c compares the two logs entry-by-entry,
 * not just the two decoders' return values -- a wrong tag or a wrong
 * vlen threaded through unchanged return codes would otherwise pass
 * silently.
 *
 * Coverage comes from three sources, not one: a handful of
 * hand-traced-by-hand "shape sanity" encodings (to confirm the harness
 * itself works before trusting its fuzzing), systematic single-byte
 * mutation of every byte position in each hand-crafted seed (targets
 * boundary/error conditions precisely), and pure random byte buffers
 * (broad, unstructured coverage of the bounds-checking).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <linux/asn1_ber_bytecode.h>

/* ---- C arm (renamed) ---- */
int cref_asn1_ber_decoder(const struct asn1_decoder *decoder, void *context,
			   const unsigned char *data, size_t datalen);

/* ---- Rust arm ---- */
int asn1_ber_decoder(const struct asn1_decoder *decoder, void *context,
		      const unsigned char *data, size_t datalen);

/*
 * x509_akid_machine, verbatim from build-full/crypto/asymmetric_keys/
 * x509_akid.asn1.c (compiled from crypto/asymmetric_keys/x509_akid.asn1
 * by scripts/asn1_compiler.c). Real, production bytecode, not invented.
 */
static const unsigned char x509_akid_machine[] = {
	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SEQ),
	ASN1_OP_MATCH_ACT_OR_SKIP,
	_tagn(CONT, PRIM, 0),
	_action(0),
	ASN1_OP_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 1),
	_jump_target(13),
	ASN1_OP_MATCH_ACT_OR_SKIP,
	_tagn(CONT, PRIM, 2),
	_action(2),
	ASN1_OP_END_SEQ,
	ASN1_OP_COMPLETE,

	ASN1_OP_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 0),
	_jump_target(39),
	ASN1_OP_COND_MATCH_OR_SKIP,
	_tagn(CONT, PRIM, 1),
	ASN1_OP_COND_MATCH_OR_SKIP,
	_tagn(CONT, PRIM, 2),
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 3),
	_jump_target(47),
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 4),
	_jump_target(50),
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 5),
	_jump_target(70),
	ASN1_OP_COND_MATCH_OR_SKIP,
	_tagn(CONT, PRIM, 6),
	ASN1_OP_COND_MATCH_OR_SKIP,
	_tagn(CONT, PRIM, 7),
	ASN1_OP_COND_MATCH_OR_SKIP,
	_tagn(CONT, PRIM, 8),
	ASN1_OP_COND_FAIL,
	ASN1_OP_END_SEQ_OF,
	_jump_target(13),
	ASN1_OP_RETURN,

	ASN1_OP_MATCH,
	_tag(UNIV, PRIM, OID),
	ASN1_OP_MATCH,
	_tagn(CONT, CONS, 0),
	ASN1_OP_MATCH_ANY,
	ASN1_OP_END_SEQ,
	ASN1_OP_END_SEQ,
	ASN1_OP_RETURN,

	ASN1_OP_MATCH_ANY,
	ASN1_OP_END_SEQ,
	ASN1_OP_RETURN,

	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SEQ),
	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SET),
	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SEQ),
	ASN1_OP_MATCH_ACT,
	_tag(UNIV, PRIM, OID),
	_action(4),
	ASN1_OP_MATCH_ANY_ACT,
	_action(3),
	ASN1_OP_END_SEQ,
	ASN1_OP_END_SET_OF,
	_jump_target(54),
	ASN1_OP_END_SEQ_OF,
	_jump_target(52),
	ASN1_OP_ACT,
	_action(1),
	ASN1_OP_END_SEQ,
	ASN1_OP_RETURN,

	ASN1_OP_MATCH_JUMP_OR_SKIP,
	_tagn(CONT, CONS, 0),
	_jump_target(79),
	ASN1_OP_MATCH,
	_tagn(CONT, CONS, 1),
	ASN1_OP_MATCH_ANY,
	ASN1_OP_END_SEQ,
	ASN1_OP_END_SEQ,
	ASN1_OP_RETURN,

	ASN1_OP_MATCH_ANY,
	ASN1_OP_END_SEQ,
	ASN1_OP_RETURN,
};

/*
 * rsapubkey_machine, verbatim from build-full/crypto/rsapubkey.asn1.c.
 * Used for indefinite-length-encoding coverage (x509_akid_machine's own
 * fields are all definite-length in practice) -- a simple two-INTEGER
 * SEQUENCE is enough to wrap in an indefinite-length outer tag and
 * confirm the EOC-handling path in END_SEQ agrees between arms.
 */
static const unsigned char rsapubkey_machine[] = {
	ASN1_OP_MATCH,
	_tag(UNIV, CONS, SEQ),
	ASN1_OP_MATCH_ACT,
	_tag(UNIV, PRIM, INT),
	_action(0),
	ASN1_OP_MATCH_ACT,
	_tag(UNIV, PRIM, INT),
	_action(1),
	ASN1_OP_END_SEQ,
	ASN1_OP_COMPLETE,
};

/* ---- action recording, shared shape for both grammars' action tables ---- */

#define MAX_CALLS 32
struct call_log_entry {
	unsigned char act;
	size_t hdrlen;
	unsigned char tag;
	size_t vlen;
	unsigned char bytes[256];
	int truncated;
};
static struct call_log_entry g_log[MAX_CALLS];
static int g_log_n;
static int g_log_overflowed;

static void reset_log(void)
{
	g_log_n = 0;
	g_log_overflowed = 0;
}

static int record(int act, void *context, size_t hdrlen, unsigned char tag,
		   const void *value, size_t vlen)
{
	(void)context;
	if (g_log_n >= MAX_CALLS) {
		g_log_overflowed = 1;
		return 0;
	}
	struct call_log_entry *e = &g_log[g_log_n++];
	e->act = (unsigned char)act;
	e->hdrlen = hdrlen;
	e->tag = tag;
	e->vlen = vlen;
	if (vlen > sizeof(e->bytes)) {
		e->truncated = 1;
		memcpy(e->bytes, value, sizeof(e->bytes));
	} else {
		e->truncated = 0;
		if (vlen)
			memcpy(e->bytes, value, vlen);
	}
	return 0;
}

/* Five distinct action slots -- matches x509_akid_action_table's shape
 * (NR__x509_akid_actions = 5). rsapubkey only ever uses slots 0/1. */
static int act0(void *c, size_t h, unsigned char t, const void *v, size_t l) { return record(0, c, h, t, v, l); }
static int act1(void *c, size_t h, unsigned char t, const void *v, size_t l) { return record(1, c, h, t, v, l); }
static int act2(void *c, size_t h, unsigned char t, const void *v, size_t l) { return record(2, c, h, t, v, l); }
static int act3(void *c, size_t h, unsigned char t, const void *v, size_t l) { return record(3, c, h, t, v, l); }
static int act4(void *c, size_t h, unsigned char t, const void *v, size_t l) { return record(4, c, h, t, v, l); }

static const asn1_action_t action_table[5] = { act0, act1, act2, act3, act4 };

static const struct asn1_decoder akid_decoder = {
	.machine = x509_akid_machine,
	.machlen = sizeof(x509_akid_machine),
	.actions = action_table,
};
static const struct asn1_decoder rsapubkey_decoder_local = {
	.machine = rsapubkey_machine,
	.machlen = sizeof(rsapubkey_machine),
	.actions = action_table,
};

static unsigned long cases, mism, n_success, n_fail, n_actions;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

/* Runs `data`/`datalen` through both arms with `decoder`, comparing
 * return value and the full action-call log entry-by-entry. */
static void check(const struct asn1_decoder *decoder, const unsigned char *data,
		   size_t datalen, const char *what)
{
	struct call_log_entry c_log[MAX_CALLS];
	int c_log_n, c_overflow;
	int rc, rr;

	cases++;

	reset_log();
	rc = cref_asn1_ber_decoder(decoder, NULL, data, datalen);
	c_log_n = g_log_n;
	c_overflow = g_log_overflowed;
	memcpy(c_log, g_log, sizeof(g_log[0]) * (size_t)c_log_n);

	reset_log();
	rr = asn1_ber_decoder(decoder, NULL, data, datalen);

	if (poison && datalen > 0 && data[0] == 0xFF)
		rr = rc + 1;

	if (rc == 0) n_success++; else n_fail++;
	n_actions += (unsigned long)c_log_n;

	if (rc != rr) {
		bad(what);
		return;
	}
	if (c_log_n != g_log_n || c_overflow != g_log_overflowed) {
		bad(what);
		return;
	}
	for (int i = 0; i < c_log_n; i++) {
		struct call_log_entry *a = &c_log[i], *b = &g_log[i];
		if (a->act != b->act || a->hdrlen != b->hdrlen || a->tag != b->tag ||
		    a->vlen != b->vlen || a->truncated != b->truncated) {
			bad(what);
			return;
		}
		size_t n = a->truncated ? sizeof(a->bytes) : a->vlen;
		if (n && memcmp(a->bytes, b->bytes, n) != 0) {
			bad(what);
			return;
		}
	}
}

static unsigned long seed;
static unsigned long xrand(void)
{
	seed ^= seed << 13;
	seed ^= seed >> 7;
	seed ^= seed << 17;
	return seed;
}

int main(void)
{
	if (getenv("ASN1_PROVE_CAN_FAIL"))
		poison = 1;
	seed = 0xD1B54A32D192ED03UL;

	/* ---- Hand-traced "shape sanity" seeds ---- */
	static const unsigned char seed_empty[] = { 0x30, 0x00 };
	static const unsigned char seed_kid[] = { 0x30, 0x04, 0x80, 0x02, 0x41, 0x42 };
	static const unsigned char seed_kid_serial[] = {
		0x30, 0x09,
		0x80, 0x02, 0x41, 0x42,       /* [0] keyIdentifier = "AB" */
		0x82, 0x01, 0x07,             /* [2] serialNumber = 7 */
	};
	/* authorityCertIssuer present: GeneralNames = SEQUENCE OF GeneralName,
	 * one directoryName [4] wrapping an empty Name (SEQUENCE OF RDN, zero
	 * RDNs), which exercises the jump into GeneralName, the [4] CHOICE
	 * arm's own jump into Name, and the two nested END_SEQ_OF/END_SET_OF
	 * loop-exit paths on their very first (zero-iteration) check. */
	static const unsigned char seed_issuer[] = {
		0x30, 0x06,                   /* AuthorityKeyIdentifier */
		0xA1, 0x04,                   /* [1] authorityCertIssuer */
		0xA4, 0x02,                   /*   GeneralName: [4] directoryName */
		0x30, 0x00,                   /*     Name ::= SEQUENCE OF RDN {} */
	};
	static const unsigned char seed_rsa[] = {
		0x30, 0x06,
		0x02, 0x01, 0x05,             /* n = 5 */
		0x02, 0x01, 0x03,             /* e = 3 */
	};
	/* Same RSA key, outer SEQUENCE re-encoded with indefinite length,
	 * terminated by EOC (00 00). */
	static const unsigned char seed_rsa_indef[] = {
		0x30, 0x80,
		0x02, 0x01, 0x05,
		0x02, 0x01, 0x03,
		0x00, 0x00,
	};

	struct {
		const struct asn1_decoder *d;
		const unsigned char *data;
		size_t len;
	} seeds[] = {
		{ &akid_decoder, seed_empty, sizeof(seed_empty) },
		{ &akid_decoder, seed_kid, sizeof(seed_kid) },
		{ &akid_decoder, seed_kid_serial, sizeof(seed_kid_serial) },
		{ &akid_decoder, seed_issuer, sizeof(seed_issuer) },
		{ &rsapubkey_decoder_local, seed_rsa, sizeof(seed_rsa) },
		{ &rsapubkey_decoder_local, seed_rsa_indef, sizeof(seed_rsa_indef) },
	};
	size_t nseeds = sizeof(seeds) / sizeof(seeds[0]);

	for (size_t i = 0; i < nseeds; i++)
		check(seeds[i].d, seeds[i].data, seeds[i].len, "seed");

	/* ---- Systematic single-byte mutation of every seed ---- */
	unsigned char buf[64];
	for (size_t i = 0; i < nseeds; i++) {
		for (size_t pos = 0; pos < seeds[i].len; pos++) {
			for (int v = 0; v < 256; v += 7) { /* every 7th value: full byte-value spread, bounded runtime */
				memcpy(buf, seeds[i].data, seeds[i].len);
				buf[pos] = (unsigned char)v;
				check(seeds[i].d, buf, seeds[i].len, "mutate");
			}
		}
		/* Truncations: every prefix length, including 0. */
		for (size_t len = 0; len <= seeds[i].len; len++)
			check(seeds[i].d, seeds[i].data, len, "truncate");
	}

	/* ---- Pure random fuzzing, both grammars, varying lengths ---- */
	for (int iter = 0; iter < 200000; iter++) {
		size_t len = (size_t)(xrand() % 40);
		for (size_t i = 0; i < len; i++)
			buf[i] = (unsigned char)(xrand() & 0xFF);
		check(iter & 1 ? &akid_decoder : &rsapubkey_decoder_local, buf, len, "random");
	}

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches (%lu success, %lu fail, %lu action calls)\n", cases, n_success, n_fail, n_actions);
	return 0;
}
