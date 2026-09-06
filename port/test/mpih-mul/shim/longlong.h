#pragma once
/* mpih-mul.c #includes "longlong.h" but never invokes any of its macros
 * directly (grep confirms: no umul_ppmm/udiv_qrnnd/count_leading_zeros/
 * add_ssaaaa/sub_ddmmss in the pristine file) -- it only needs the
 * #include to resolve to something. Unlike port/test/mpih-div/'s harness,
 * which checks the Rust reimplementation of those macros and therefore
 * needs the genuine upstream file, nothing here exercises this header's
 * content, so an empty shim is faithful rather than a shortcut. */
