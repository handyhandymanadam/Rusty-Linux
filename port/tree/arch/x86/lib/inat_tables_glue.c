// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RUST PORT (arch/x86/lib/inat.c, 6.18.49): the generated x86 opcode attribute
 * tables, and nothing else. The six inat_get_*() lookups that used to follow
 * them in inat.c are in insn_rs.rs, which reads these tables as extern data.
 * Upstream's inat.c is installed as inat_norust.c for CONFIG_RUST=n.
 */
#include <asm/insn.h> /* __ignore_sync_check__ */

#include "inat-tables.c"
