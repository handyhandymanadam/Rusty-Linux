/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * port/test/oid_registry/drv.c -- differential for lib/oid_registry.c.
 *
 * Exercises every real OID's own encoded bytes (must round-trip through
 * look_up_OID), every real OID wrapped in the ASN1_OID|len| header (must
 * round-trip through parse_OID), sprint_oid on every real OID's bytes,
 * plus deliberately malformed/edge inputs (empty, truncated, unknown,
 * buffer-too-small) on both arms.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;

/* ---- C arm (renamed) ---- */
int c_look_up_OID(const void *data, size_t datasize);
int c_parse_OID(const void *data, size_t datasize, int *oid);
int c_sprint_oid(const void *data, size_t datasize, char *buffer, size_t bufsize);

/* ---- Rust arm ---- */
int look_up_OID(const void *data, size_t datasize);
int parse_OID(const void *data, size_t datasize, int *oid);
int sprint_oid(const void *data, size_t datasize, char *buffer, size_t bufsize);

/* The real OID byte-encodings, extracted from the same generated
 * oid_registry_data.c both arms are built from -- see run.sh. */
#include "oid_table.h"

static unsigned long cases, mism;
static int poison;

static void bad(const char *what)
{
	if (mism < 20)
		printf("MISMATCH %s\n", what);
	mism++;
}

static void check_lookup(const u8 *data, size_t len, int expect_found)
{
	int c = c_look_up_OID(data, len);
	int r = look_up_OID(data, len);
	cases++;
	if (poison && len > 0 && data[0] == 0xFF)
		r = c + 1; /* prove-can-fail */
	if (c != r)
		bad("look_up_OID");
	if (expect_found >= 0 && c != expect_found)
		bad("look_up_OID-vs-expected");
}

static void check_parse(const u8 *hdr, size_t len)
{
	/* Same initial value on both arms: parse_OID's early-return paths
	 * (bad tag, bad length, too short) leave *oid untouched, matching
	 * real C behaviour -- comparing against DIFFERENT sentinels there
	 * would be a test-harness bug, not a port one. */
	int oid_c = -1, oid_r = -1;
	int rc = c_parse_OID(hdr, len, &oid_c);
	int rr = parse_OID(hdr, len, &oid_r);
	cases++;
	if (rc != rr || oid_c != oid_r)
		bad("parse_OID");
}

static void check_sprint(const u8 *data, size_t len, size_t bufsize)
{
	char bc[256], br[256];
	memset(bc, 0xAA, sizeof(bc));
	memset(br, 0xAA, sizeof(br));
	int rc = c_sprint_oid(data, len, bc, bufsize);
	int rr = sprint_oid(data, len, br, bufsize);
	cases++;
	if (rc != rr)
		bad("sprint_oid-retval");
	/* Only the bytes up to bufsize are contractually defined. */
	if (bufsize > 0 && memcmp(bc, br, bufsize) != 0)
		bad("sprint_oid-buffer");
}

int main(void)
{
	if (getenv("OID_PROVE_CAN_FAIL"))
		poison = 1;

	for (size_t i = 0; i < OID_TABLE_LEN; i++) {
		const u8 *data = oid_table[i].data;
		size_t len = oid_table[i].len;

		check_lookup(data, len, (int)i);

		u8 hdr[300];
		hdr[0] = 6; /* ASN1_OID */
		hdr[1] = (u8)len;
		memcpy(hdr + 2, data, len);
		check_parse(hdr, len + 2);

		for (size_t b = 0; b <= 8; b++)
			check_sprint(data, len, b);
		check_sprint(data, len, 256);
	}

	/* Edge cases both arms must agree on. */
	check_lookup(NULL, 0, -1);
	{
		u8 unknown[] = { 0xFF, 0xFF, 0xFF };
		check_lookup(unknown, sizeof(unknown), -1);
	}
	{
		u8 hdr[] = { 6, 2 }; /* claims 2 bytes of OID, has 0 */
		check_parse(hdr, sizeof(hdr));
	}
	{
		u8 hdr[] = { 7, 3, 1, 2, 3 }; /* wrong tag, not ASN1_OID */
		check_parse(hdr, sizeof(hdr));
	}
	check_parse(NULL, 0);
	check_parse(NULL, 2);
	{
		/* Truncated continuation byte in sprint_oid's multi-byte
		 * component decoder. */
		u8 data[] = { 42, 0x81 };
		check_sprint(data, sizeof(data), 256);
	}
	check_sprint(NULL, 0, 256);
	check_sprint(NULL, 0, 0);

	if (mism) {
		fprintf(stderr, "%lu/%lu cases MISMATCHED\n", mism, cases);
		return 1;
	}
	printf("%lu cases, 0 mismatches\n", cases);
	return 0;
}
