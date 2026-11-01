/* Reference for the early command-line pass of init/main.c: the REAL C (early_gen.py), on top of params_ref.c's real parse_args / next_arg. */
#include "params_shim.h"
#define __init
#define __initdata __attribute__((section("early_initdata")))
#define COMMAND_LINE_SIZE 2048
#define strscpy(d, s, n) sized_strscpy(d, s, n)
#define parse_early_options c_parse_early_options
#define parse_early_param c_parse_early_param
struct obs_kernel_param { const char *str; int (*setup_func)(char *); int early; };
extern struct obs_kernel_param __setup_start[], __setup_end[];
extern char boot_command_line[COMMAND_LINE_SIZE];
long sized_strscpy(char *dst, const char *src, size_t count);
bool parameq(const char *a, const char *b);
char *parse_args(const char *doing, char *args, const struct kernel_param *params, unsigned num, s16 min_level, s16 max_level, void *arg, parse_unknown_fn unknown);
#include EARLYINC
#undef parse_early_options
#undef parse_early_param
/* the table: 24 entries, `__setup_end` right after it */
#define NSET 24
struct obs_kernel_param __setup_start[NSET];
__asm__(".globl __setup_end\n.set __setup_end, __setup_start + 24*24\n");
char boot_command_line[COMMAND_LINE_SIZE];
extern bool c_parameq(const char *a, const char *b);
extern char *c_parse_args(const char *, char *, const struct kernel_param *, unsigned, s16, s16, void *, parse_unknown_fn);
bool parameq(const char *a, const char *b) { return c_parameq(a, b); }
char *parse_args(const char *doing, char *args, const struct kernel_param *params, unsigned num, s16 min_level, s16 max_level, void *arg, parse_unknown_fn unknown)
{ return c_parse_args(doing, args, params, num, min_level, max_level, arg, unknown); }
long sized_strscpy(char *dst, const char *src, size_t count)
{ size_t n = strlen(src); if (count == 0) return -7; size_t c = n < count ? n : count - 1; memcpy(dst, src, c); dst[c] = 0; return n < count ? (long)n : -7; }
extern int setup_cb(int idx, char *val);
#define SF(i) static int sf##i(char *v) { return setup_cb(i, v); }
SF(0) SF(1) SF(2) SF(3) SF(4) SF(5) SF(6) SF(7) SF(8) SF(9) SF(10) SF(11) SF(12) SF(13) SF(14) SF(15) SF(16) SF(17) SF(18) SF(19) SF(20) SF(21) SF(22) SF(23)
int (*const sf_tab[NSET])(char *) = { sf0, sf1, sf2, sf3, sf4, sf5, sf6, sf7, sf8, sf9, sf10, sf11, sf12, sf13, sf14, sf15, sf16, sf17, sf18, sf19, sf20, sf21, sf22, sf23 };
void *e_table(void) { return __setup_start; }
void *e_cmdline(void) { return boot_command_line; }
void *e_sf(int i) { return (void *)sf_tab[i]; }
void e_c_early(void) { c_parse_early_param(); }
extern char __start_early_initdata[], __stop_early_initdata[];
void e_reset(void) { memset(__start_early_initdata, 0, __stop_early_initdata - __start_early_initdata); }
