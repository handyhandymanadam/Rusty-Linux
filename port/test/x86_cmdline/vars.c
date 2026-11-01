#include <asm/cmdline.h>
char builtin_cmdline[COMMAND_LINE_SIZE];
#ifdef WITH_BOOL
bool builtin_cmdline_added;
#endif
