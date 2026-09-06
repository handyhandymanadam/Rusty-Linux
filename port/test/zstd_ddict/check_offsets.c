/* SPDX-License-Identifier: GPL-2.0
 *
 * Mechanical proof that zstd_ddict_rs.rs's two mirrored structs --
 * `ZstdDCtx` (its own copy, independent of zstd_decompress_block_rs.rs's)
 * and `ZstdDDict` -- match `struct ZSTD_DCtx_s` and `struct ZSTD_DDict_s`
 * (zstd_decompress_internal.h / zstd_ddict.c) field for field. Diffed
 * against offsets.rs's offset_of!() by check_offsets.sh.
 */
#include <stddef.h>
#include <stdio.h>
#include "mem.h"
#include "zstd_internal.h"
#include "zstd_decompress_internal.h"
#include "zstd_ddict.h"

/* struct ZSTD_DDict_s is private to zstd_ddict.c; redeclare it here
 * identically (zstd_ddict.c:34-42) so offsetof() can see its fields. Kept
 * in sync by pristine-check.sh's byte-for-byte guarantee on that file. */
struct ZSTD_DDict_s {
    void* dictBuffer;
    const void* dictContent;
    size_t dictSize;
    ZSTD_entropyDTables_t entropy;
    U32 dictID;
    U32 entropyPresent;
    ZSTD_customMem cMem;
};

#define P(field) printf("%-24s %zu\n", #field, offsetof(struct ZSTD_DCtx_s, field))
#define PD(field) printf("%-24s %zu\n", #field, offsetof(struct ZSTD_DDict_s, field))

int main(void) {
    printf("sizeof(struct ZSTD_DCtx_s) = %zu\n", sizeof(struct ZSTD_DCtx_s));
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

    printf("sizeof(struct ZSTD_DDict_s) = %zu\n", sizeof(struct ZSTD_DDict_s));
    PD(dictBuffer); PD(dictContent); PD(dictSize); PD(entropy); PD(dictID);
    PD(entropyPresent); PD(cMem);
    return 0;
}
/* satisfies error_private.h's static-inline link dependency; not exercised. */
const char* ERR_getErrorString(ERR_enum x) { (void)x; return ""; }
