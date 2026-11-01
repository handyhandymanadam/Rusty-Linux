/* Stand-ins for what the pristine slice of kernel/auditfilter.c uses. The AUDIT_* / Audit_* definitions are the kernel's uapi header, extracted by run.sh into audit_consts.h. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
typedef uint32_t u32;
#define EINVAL 22
#define AF_MAX 46
#define AUDIT_NAME_FULL -1
#include "audit_consts.h"
typedef struct { uint32_t val; } kuid_t; typedef struct { uint32_t val; } kgid_t;
#define __kuid_val(k) ((k).val)
#define __kgid_val(k) ((k).val)
#define uid_eq(a, b) ((a).val == (b).val)
#define uid_lt(a, b) ((a).val < (b).val)
#define uid_lte(a, b) ((a).val <= (b).val)
#define uid_gt(a, b) ((a).val > (b).val)
#define uid_gte(a, b) ((a).val >= (b).val)
#define gid_eq uid_eq
#define gid_lt uid_lt
#define gid_lte uid_lte
#define gid_gt uid_gt
#define gid_gte uid_gte
struct qstr { const unsigned char *name; uint32_t len; };
struct audit_field { u32 type, op, val; }; struct audit_entry { struct { u32 listnr; } rule; };
#define static_assert(x) _Static_assert(1, "")
#endif
