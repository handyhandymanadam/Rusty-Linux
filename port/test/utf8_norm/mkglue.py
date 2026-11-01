#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- utf8_norm_glue.c: what is left of fs/unicode/utf8-norm.c once everything is in utf8_norm_rs.rs (layout checks + upstream's KUnit export block)."""
import sys
s = open(sys.argv[1]).read()
tail = s[s.index("#if IS_MODULE(CONFIG_UNICODE_NORMALIZATION_KUNIT_TEST)"):]
head = '''// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUST PORT (fs/unicode/utf8-norm.c, 6.18.49): the whole file is in utf8_norm_rs.rs. This file only checks the structure layouts the Rust hard-codes and keeps upstream's
 * export block for the KUnit-as-module configuration (not built here; with it, the exports need the usual thunk treatment). Upstream's file is installed as utf8-norm_norust.c
 * for CONFIG_RUST=n.
 */

#include "utf8n.h"

static_assert(sizeof(struct utf8data) == 8 && offsetof(struct utf8data, maxage) == 0 && offsetof(struct utf8data, offset) == 4);
static_assert(sizeof(struct utf8data_table) == 56 && offsetof(struct utf8data_table, utf8agetab) == 0 && offsetof(struct utf8data_table, utf8agetab_size) == 8 &&
	      offsetof(struct utf8data_table, utf8nfdicfdata) == 16 && offsetof(struct utf8data_table, utf8nfdicfdata_size) == 24 &&
	      offsetof(struct utf8data_table, utf8nfdidata) == 32 && offsetof(struct utf8data_table, utf8nfdidata_size) == 40 && offsetof(struct utf8data_table, utf8data) == 48);
static_assert(sizeof(struct unicode_map) == 32 && offsetof(struct unicode_map, version) == 0 && offsetof(struct unicode_map, ntab) == 8 && offsetof(struct unicode_map, tables) == 24 &&
	      UTF8_NMAX == 2);
static_assert(sizeof(struct utf8cursor) == 72 && offsetof(struct utf8cursor, um) == 0 && offsetof(struct utf8cursor, n) == 8 && offsetof(struct utf8cursor, s) == 16 &&
	      offsetof(struct utf8cursor, p) == 24 && offsetof(struct utf8cursor, ss) == 32 && offsetof(struct utf8cursor, sp) == 40 && offsetof(struct utf8cursor, len) == 48 &&
	      offsetof(struct utf8cursor, slen) == 52 && offsetof(struct utf8cursor, ccc) == 56 && offsetof(struct utf8cursor, nccc) == 58 && offsetof(struct utf8cursor, hangul) == 60 &&
	      UTF8HANGULLEAF == 12);

'''
open(sys.argv[2], "w").write(head + tail)
