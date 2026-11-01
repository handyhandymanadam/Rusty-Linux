/* Stand-ins for what the pristine slice of fs/fs_parser.c uses. */
#ifndef REFSHIM_H
#define REFSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
typedef uint8_t u8; typedef uint32_t u32; typedef unsigned long long u64;
#define ENOPARAM 519
#define likely(x) __builtin_expect(!!(x), 1)
#define static_assert(x) _Static_assert(x, #x)
#define EXPORT_SYMBOL(x)
enum fs_value_type { fs_value_is_undefined, fs_value_is_flag, fs_value_is_string, fs_value_is_blob, fs_value_is_filename, fs_value_is_file };
struct p_log { const char *prefix; void *log; };
struct fs_parameter { const char *key; enum fs_value_type type:8; union { char *string; void *blob; void *name; void *file; }; size_t size; int dirfd; };
typedef struct { u32 val; } kuid_t; typedef struct { u32 val; } kgid_t;
struct constant_table { const char *name; int value; };
struct fs_parameter_spec; struct fs_parse_result;
typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);
struct fs_parameter_spec { const char *name; fs_param_type *type; u8 opt; unsigned short flags;
#define fs_param_neg_with_no 0x0002
#define fs_param_can_be_empty 0x0004
#define fs_param_deprecated 0x0008
	const void *data; };
struct fs_parse_result { bool negated; union { bool boolean; int int_32; unsigned int uint_32; u64 uint_64; kuid_t uid; kgid_t gid; }; };
extern const struct constant_table bool_names[];
/* logging: every message is printed with its level, so the texts, the keys and the order are compared */
extern int log_n;
static inline void plog_(struct p_log *p, char lvl, const char *fmt, const char *arg) { log_n++; printf("    log %c %s: ", lvl, p->prefix ? p->prefix : "-"); printf(fmt, arg); printf("\n"); }
#define warn_plog(p, fmt, ...) plog_(p, 'w', fmt, ##__VA_ARGS__)
#define error_plog(p, fmt, ...) plog_(p, 'e', fmt, ##__VA_ARGS__)
#define inval_plog(p, fmt, ...) (error_plog(p, fmt, ## __VA_ARGS__), -EINVAL)
int kstrtouint(const char *s, unsigned int base, unsigned int *res);
int kstrtoint(const char *s, unsigned int base, int *res);
int kstrtoull(const char *s, unsigned int base, unsigned long long *res);
#define current_user_ns() ((void *)0)
extern u32 uid_limit;
static inline kuid_t make_kuid(void *ns, u32 v) { kuid_t k = { v >= uid_limit ? (u32)-1 : v + 1000 }; return k; }
static inline kgid_t make_kgid(void *ns, u32 v) { kgid_t k = { v >= uid_limit ? (u32)-1 : v + 2000 }; return k; }
#define uid_valid(u) ((u).val != (u32)-1)
#define gid_valid(g) ((g).val != (u32)-1)
#define __kuid_val(u) ((u).val)
#define __kgid_val(g) ((g).val)
#endif
