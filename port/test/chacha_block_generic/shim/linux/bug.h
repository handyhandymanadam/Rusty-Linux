#pragma once
/* WARN_ON_ONCE's return value (whether the condition was true) is not used
 * by chacha_permute(); the side effect (a dmesg splat) is not this harness's
 * concern. */
#define WARN_ON_ONCE(cond) ((void)(cond))
