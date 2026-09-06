/* SPDX-License-Identifier: GPL-2.0
 *
 * Test-only stand-in for ZSTD_loadDEntropy, which lives in zstd_decompress.c
 * -- a file neither arm here ports or owns. Deterministic and identical for
 * both arms, so this harness proves zstd_ddict's/zstd_ddict_rs.rs's OWN
 * propagation of the call (dictID parsing before the call, entropyPresent
 * and error-code handling after it), not zstd_decompress.c's real
 * entropy-table-building logic.
 *
 * Rule: fails (returns a corruption error) iff dictSize is a multiple of 7;
 * otherwise writes recognizable, distinct values into entropy->rep so
 * ZSTD_copyDDictParameters's copy of them is independently checkable.
 */
#include <stddef.h>
#include <string.h>

/* ZSTD_entropyDTables_t's `rep` field is 12 bytes (3x U32) at a fixed
 * offset from the struct's start that neither arm's own layout disagrees on
 * (both already offsetof()-checked against the real header). Since this
 * stub only ever touches `rep`, reach it via the byte offset rather than
 * pulling in the whole struct definition here -- this file is deliberately
 * independent of both arms' struct mirrors.
 */
#define ENTROPY_REP_BYTE_OFFSET 26652u /* offsetof(ZSTD_entropyDTables_t, rep), independently confirmed */

static size_t fake_load_dentropy(void *entropy, const void *dict, size_t dictSize)
{
	(void)dict;
	if (dictSize % 7 == 0)
		return (size_t)-30; /* ZSTD_error_dictionary_corrupted */
	{
		unsigned int rep[3] = { 0x11111111u, 0x22222222u, 0x33333333u };
		memcpy((char *)entropy + ENTROPY_REP_BYTE_OFFSET, rep, sizeof(rep));
	}
	return 0;
}

size_t ZSTD_loadDEntropy(void *entropy, const void *dict, size_t dictSize)
{
	return fake_load_dentropy(entropy, dict, dictSize);
}

size_t ref_ZSTD_loadDEntropy(void *entropy, const void *dict, size_t dictSize)
{
	return fake_load_dentropy(entropy, dict, dictSize);
}
