# SPDX-License-Identifier: GPL-2.0-only
# int_pow.c, int_sqrt.c, lcm.c and rational.c are gone: their Rust defines and
# exports those symbols itself and carries their ABI contracts, via
# kernel::kabi_export!(). See logs/c-entry-rule.md.

obj-$(CONFIG_MATH_SELFTEST)	+= mathtest.o

obj-$(CONFIG_CORDIC)		+= cordic.o
obj-$(CONFIG_PRIME_NUMBERS)	+= prime_numbers.o
obj-$(CONFIG_RATIONAL)		+=

obj-$(CONFIG_TEST_DIV64)	+= test_div64.o
obj-$(CONFIG_TEST_MULDIV64)	+= test_mul_u64_u64_div_u64.o

obj-y += tests/

# --- THE CONFIG_RUST=n ARM.  logs/floor.md RAISE 2. ------------------------
# <base>_norust.c is installed by rig/apply.sh from port/pristine/ -- the
# sha256-verified upstream body, byte for byte, at a filename the Makefile can
# choose independently of the ported one. Generated on every apply, never
# committed, so it cannot drift.
ifdef CONFIG_RUST
obj-y                  += div64.o gcd.o int_log.o reciprocal_div.o
obj-y                  += int_pow_rs.o int_sqrt_rs.o int_log_rs.o reciprocal_div_rs.o
obj-y                  += gcd_rs.o lcm_rs.o div64_rs.o
obj-$(CONFIG_RATIONAL) += rational_rs.o
else
obj-y                  += div64_norust.o gcd_norust.o int_log_norust.o \
                          reciprocal_div_norust.o int_pow_norust.o \
                          int_sqrt_norust.o lcm_norust.o
obj-$(CONFIG_RATIONAL) += rational_norust.o
endif
