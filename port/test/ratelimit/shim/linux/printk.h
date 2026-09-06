#pragma once
#define KERN_WARNING "\0014"
int _printk_deferred(const char *fmt, ...);
#define printk_deferred(fmt, ...) _printk_deferred(fmt, ##__VA_ARGS__)
