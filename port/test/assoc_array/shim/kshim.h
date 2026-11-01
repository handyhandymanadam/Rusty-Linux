/* Userspace stand-ins for the kernel pieces lib/assoc_array.c (and its glue) use. */
#ifndef KSHIM_H
#define KSHIM_H
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
#define BITS_PER_LONG 64
#define ULONG_MAX (~0UL)
#define INT_MAX_ 0x7fffffff
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define READ_ONCE(x) (*(volatile __typeof__(x) *)&(x))
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define fallthrough __attribute__((__fallthrough__))
#define pr_devel(...) do { } while (0)
#define ilog2(x) ((int)(63 - __builtin_clzl((unsigned long)(x))))
#define __ffs(x) ((unsigned long)__builtin_ctzl(x))
#define round_up(x, y) ((((x) - 1) | ((y) - 1)) + 1)
#define round_down(x, y) ((x) & ~((y) - 1))
#define struct_size(p, member, n) (sizeof(*(p)) + sizeof((p)->member[0]) * (n))
#define flex_array_size(p, member, n) (sizeof((p)->member[0]) * (n))
#define GFP_KERNEL 0
typedef unsigned gfp_t;
extern void h_bug(void) __attribute__((noreturn));
#define BUG() h_bug()
#define BUG_ON(c) do { if (c) h_bug(); } while (0)
#define ERR_PTR(e) ((void *)(long)(e))
#define IS_ERR(p) ((unsigned long)(void *)(p) >= (unsigned long)-4095)
void *h_zalloc(size_t n); void *h_malloc(size_t n); void h_free(void *p);
#define kzalloc(n, f) h_zalloc(n)
#define kmalloc(n, f) h_malloc(n)
#define kfree(p) h_free(p)
struct rcu_head { struct rcu_head *next; void (*func)(struct rcu_head *); };
void h_call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *));
#define call_rcu(h, f) h_call_rcu((h), (f))
#define static_assert _Static_assert
#define CONFIG_ASSOCIATIVE_ARRAY 1
#endif
