#include <linux/init.h>
#include <linux/nls.h>
/* The registry is not under test; record that registration was asked for. */
int register_calls;
int __register_nls(struct nls_table *n, struct module *m) { (void)m; (void)n; register_calls++; return 0; }
int unregister_nls(struct nls_table *n) { (void)n; return 0; }
