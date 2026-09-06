#pragma once
#include <stdio.h>
#include <stdlib.h>
#define WARN_ON(cond) \
	({ bool __ret = !!(cond); if (__ret) fprintf(stderr, "WARN_ON: " #cond "\n"); __ret; })
#define WARN_ON_ONCE(cond) WARN_ON(cond)
#define BUILD_BUG_ON(cond) _Static_assert(!(cond), #cond)
#define BUG_ON(cond) \
	do { if (cond) { fprintf(stderr, "BUG_ON: " #cond "\n"); abort(); } } while (0)
