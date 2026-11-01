/* shim for the kobject_uevent differential: the types and stubs the synthetic-uevent parser and zap_modalias_env() touch. */
#ifndef SH_KOBJECT_UE_H
#define SH_KOBJECT_UE_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#undef isalnum
/* the kernel's isalnum(): its _ctype table makes 0xc0-0xff letters except 0xd7 and 0xf7 */
static inline int ke_isalnum(int c) { unsigned char u = (unsigned char)c; return (u >= '0' && u <= '9') || (u >= 'A' && u <= 'Z') || (u >= 'a' && u <= 'z') || (u >= 0xc0 && u != 0xd7 && u != 0xf7); }
#define isalnum(c) ke_isalnum(c)
#define KERN_ERR ""
#define UEVENT_NUM_ENVP 64
#define UEVENT_BUFFER_SIZE 2048
#define UUID_STRING_LEN 36
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define GFP_KERNEL 0
typedef unsigned int gfp_t;
enum kobject_action { KOBJ_ADD, KOBJ_REMOVE, KOBJ_CHANGE, KOBJ_MOVE, KOBJ_ONLINE, KOBJ_OFFLINE, KOBJ_BIND, KOBJ_UNBIND };
struct kobject { int id; };
struct kobj_uevent_env {
	char *argv[3];
	char *envp[UEVENT_NUM_ENVP];
	int envp_idx;
	char buf[UEVENT_BUFFER_SIZE];
	int buflen;
};
extern int warn_count;
void klog(const char *tag, const char *fmt, ...);
#define pr_warn(fmt, ...) klog("pr_warn", fmt, ##__VA_ARGS__)
#define WARN(c, fmt, ...) ({ int __r = !!(c); if (__r) { warn_count++; klog("WARN", fmt, ##__VA_ARGS__); } __r; })
#define EXPORT_SYMBOL_GPL(x)
void *kzalloc(size_t n, gfp_t g); void kfree(const void *p);
static inline char *strnchr(const char *s, size_t count, int c) { while (count--) { if (*s == (char)c) return (char *)s; if (*s++ == '\0') break; } return NULL; }
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action, char *envp[]);
char *kobject_get_path(const struct kobject *kobj, gfp_t gfp);
bool uuid_is_valid(const char *uuid);
#endif
