#ifndef SHIM_SECURITY_H
#define SHIM_SECURITY_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct extended_perms_data { u32 p[8]; };
struct extended_perms { int dummy; };
struct extended_perms_decision { int dummy; };
struct av_decision { u32 allowed, auditallow, auditdeny, seqno, flags; };
#endif
