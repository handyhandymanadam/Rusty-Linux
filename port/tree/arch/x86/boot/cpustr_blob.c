// SPDX-License-Identifier: GPL-2.0-only
/*
 * RUSTY-LINUX: the C compiler's own image of x86_cap_strs[] (cpustr.h, written by the hostprog
 * mkcpustr), as the only object of this file. The Makefile turns its .rodata into cpustr.bin,
 * which cpu_rs.rs include_bytes!s, so the Rust walks byte for byte the table cpu.c would have.
 */
#define static
#include "cpustr.h"
