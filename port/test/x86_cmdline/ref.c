/* The pristine arch/x86/lib/cmdline.c compiled as-is (shimmed headers); the
 * entry points are renamed c_*, and the two static workers get wrappers so the
 * test can drive them with any max_cmdline_size. */
#define cmdline_find_option_bool c_cmdline_find_option_bool
#define cmdline_find_option c_cmdline_find_option
#include CMDLINE_PRISTINE_C
#undef cmdline_find_option_bool
#undef cmdline_find_option
int c_worker_bool(const char *c, int max, const char *o) { return __cmdline_find_option_bool(c, max, o); }
int c_worker_opt(const char *c, int max, const char *o, char *b, int n) { return __cmdline_find_option(c, max, o, b, n); }
