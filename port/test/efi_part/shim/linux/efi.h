#ifndef SHIM_EFI_H
#define SHIM_EFI_H
#include "../../refshim.h"
typedef struct { u8 b[16]; } efi_guid_t;
#define NULL_GUID ((efi_guid_t){ { 0 } })
static inline int efi_guidcmp(efi_guid_t left, efi_guid_t right) { return memcmp(&left, &right, sizeof(efi_guid_t)); }
#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) ((efi_guid_t){ { (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, ((a) >> 24) & 0xff, (b) & 0xff, ((b) >> 8) & 0xff, (c) & 0xff, ((c) >> 8) & 0xff, d0, d1, d2, d3, d4, d5, d6, d7 } })
#endif
