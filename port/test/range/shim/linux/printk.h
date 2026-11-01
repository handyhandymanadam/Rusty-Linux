void kshim_printk(const char *func, const char *msg);
#define pr_err(fmt, ...) kshim_printk("subtract_range", fmt)
