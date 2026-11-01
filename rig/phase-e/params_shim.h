/* Userspace stand-ins for the C cut out of the pristine kernel/params.c (+ next_arg of lib/cmdline.c). The two struct layouts are
 * the kernel's own text (moduleparam.h); every kernel service the code calls is a recorded stub (see params_ref.c). */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
typedef int8_t s8; typedef int16_t s16; typedef uint8_t u8; typedef uint16_t u16;
#define ENOENT 2
#define EPERM 1
#define EINVAL 22
#define ENOSPC 28
#define NULL ((void *)0)
#define ERR_PTR(x) ((void *)(long)(x))
struct module;
struct kernel_param;
struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *val, const struct kernel_param *kp);
	int (*get)(char *buffer, const struct kernel_param *kp);
	void (*free)(void *arg);
};
enum { KERNEL_PARAM_OPS_FL_NOARG = (1 << 0) };
enum { KERNEL_PARAM_FL_UNSAFE = (1 << 0), KERNEL_PARAM_FL_HWPARAM = (1 << 1) };
struct kparam_string; struct kparam_array;
struct kernel_param {
	const char *name; struct module *mod; const struct kernel_param_ops *ops; const u16 perm; s8 level; u8 flags;
	union { void *arg; const struct kparam_string *str; const struct kparam_array *arr; };
};
_Static_assert(sizeof(struct kernel_param) == 40 && offsetof(struct kernel_param, level) == 26 && offsetof(struct kernel_param_ops, set) == 8, "layout");
typedef int (*parse_unknown_fn)(char *param, char *val, const char *doing, void *arg);
int _printk(const char *fmt, ...);
#define pr_err(fmt, ...)    _printk("\0013" fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)   _printk("\0014" fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...) _printk("\0015" fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)  do { } while (0)
#define LOCKDOWN_MODULE_PARAMETERS 4
#define TAINT_USER 6
#define LOCKDEP_STILL_OK 1
int security_locked_down(int what);
void add_taint(unsigned flag, int lockdep);
void kernel_param_lock(struct module *mod);
void kernel_param_unlock(struct module *mod);
bool test_irqs_disabled(void);
#define irqs_disabled() test_irqs_disabled()
static inline int isspace(int c) { return c == ' ' || (c >= 9 && c <= 13); }
static inline char *skip_spaces(const char *str) { while (isspace((unsigned char)*str)) ++str; return (char *)str; }
