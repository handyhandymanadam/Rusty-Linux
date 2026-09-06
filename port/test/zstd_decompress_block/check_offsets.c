/* SPDX-License-Identifier: GPL-2.0
 *
 * Mechanical proof that `ZstdDCtx` (zstd_decompress_block_rs.rs) mirrors
 * `struct ZSTD_DCtx_s` (zstd_decompress_internal.h) field-for-field: every
 * field's offsetof() here is diffed against offsets.rs's offset_of!() for
 * the same field name, by check_offsets.sh. The only expected diff between
 * the two outputs is the struct's own name in the header line.
 *
 * This full-struct mirror is what zstd_decompress_block.c needs, unlike
 * inffast_rs.rs's InflateState: the 24 dctx-> fields this file touches are
 * scattered from the struct's first field to its last (grep dctx-> across
 * the pristine C), so every field in between must also be declared, with a
 * same-size/alignment type, purely to keep every later field's offset
 * correct -- see the module doc comment in zstd_decompress_block_rs.rs.
 */
#include <stddef.h>
#include <stdio.h>
#include "mem.h"
#include "zstd_internal.h"
#include "zstd_decompress_internal.h"

#define P(field) printf("%-24s %zu\n", #field, offsetof(struct ZSTD_DCtx_s, field))

int main(void) {
    printf("sizeof(struct ZSTD_DCtx_s) = %zu\n", sizeof(struct ZSTD_DCtx_s));
    printf("sizeof(ZSTD_entropyDTables_t) = %zu\n", sizeof(ZSTD_entropyDTables_t));
    printf("sizeof(ZSTD_seqSymbol) = %zu\n", sizeof(ZSTD_seqSymbol));
    P(LLTptr); P(MLTptr); P(OFTptr); P(HUFptr); P(entropy); P(workspace);
    P(previousDstEnd); P(prefixStart); P(virtualStart); P(dictEnd);
    P(expected); P(fParams); P(processedCSize); P(decodedSize);
    P(bType); P(stage); P(litEntropy); P(fseEntropy); P(xxhState);
    P(headerSize); P(format); P(forceIgnoreChecksum); P(validateChecksum);
    P(litPtr); P(customMem); P(litSize); P(rleSize); P(staticSize);
    P(isFrameDecompression);
#if DYNAMIC_BMI2
    P(bmi2);
#endif
    P(ddictLocal); P(ddict); P(dictID); P(ddictIsCold); P(dictUses);
    P(ddictSet); P(refMultipleDDicts); P(disableHufAsm); P(maxBlockSizeParam);
    P(streamStage); P(inBuff); P(inBuffSize); P(inPos); P(maxWindowSize);
    P(outBuff); P(outBuffSize); P(outStart); P(outEnd); P(lhSize);
    P(hostageByte); P(noForwardProgress); P(outBufferMode); P(expectedOutBuffer);
    P(litBuffer); P(litBufferEnd); P(litBufferLocation); P(litExtraBuffer);
    P(headerBuffer); P(oversizedDuration);
    return 0;
}
/* satisfies error_private.h's static-inline link dependency; not exercised. */
const char* ERR_getErrorString(ERR_enum x) { (void)x; return ""; }
