/* Reference for params.c: the REAL C cut out of the pristine files (params_gen.py), names prefixed c_ so the Rust ones can be linked beside them. */
#define skip_spaces c_skip_spaces
#include "params_shim.h"
#define parameq c_parameq
#define parameqn c_parameqn
#define parse_one c_parse_one
#define parse_args c_parse_args
#define param_check_unsafe c_param_check_unsafe
#define next_arg c_next_arg
char *next_arg(char *args, char **param, char **val);
#include PARAMSINC
#undef param_check_unsafe
#undef skip_spaces
#undef next_arg
extern void log_event(int kind, long a, long b);
extern void log_msg(const char *text, int len);
static int g_lockdown; static bool g_irq;
void set_lockdown(int v) { g_lockdown = v; }
void set_irq(bool v) { g_irq = v; }
bool test_irqs_disabled(void) { return g_irq; }
int security_locked_down(int what) { log_event(1, what, 0); return g_lockdown; }
void add_taint(unsigned flag, int lockdep) { log_event(2, flag, lockdep); }
void kernel_param_lock(struct module *mod) { log_event(3, (long)mod, 0); }
void kernel_param_unlock(struct module *mod) { log_event(4, (long)mod, 0); }
int _printk(const char *fmt, ...) { char b[1200]; va_list ap; va_start(ap, fmt); int n = vsnprintf(b, sizeof b, fmt + 2, ap); va_end(ap);
	char t[1300]; t[0] = fmt[1]; memcpy(t + 1, b, n < 1199 ? n : 1199); log_msg(t, 1 + (n < 1199 ? n : 1199)); return n; }
/* the Rust code calls these two (and param_check_unsafe) by the kernel names */
char *next_arg(char *args, char **param, char **val) { return c_next_arg(args, param, val); }
char *skip_spaces(const char *s) { return c_skip_spaces(s); }
bool param_check_unsafe(const struct kernel_param *kp) { return c_param_check_unsafe(kp); }
bool ref_parameq(const char *a, const char *b) { return c_parameq(a, b); }
bool ref_parameqn(const char *a, const char *b, size_t n) { return c_parameqn(a, b, n); }
char *ref_parse_args(const char *doing, char *args, const struct kernel_param *params, unsigned num, s16 min_level, s16 max_level, void *arg, parse_unknown_fn unknown)
{ return c_parse_args(doing, args, params, num, min_level, max_level, arg, unknown); }
