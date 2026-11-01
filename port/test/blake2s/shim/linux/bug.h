#pragma once
/* Neither WARN_ON's side effect (a dmesg splat) nor IS_ENABLED(DEBUG)'s real
 * Kconfig meaning are this harness's concern -- both are dead in every real
 * kernel build too (see blake2s_rs.rs's own module doc on `DEBUG`). */
#define WARN_ON(cond) ((void)(cond))
#define IS_ENABLED(x) 0
