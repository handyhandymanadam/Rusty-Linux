/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kabi.h -- MODVERSIONS fingerprint pins for symbols whose body moved to Rust.
 *
 * WHY THIS FILE EXISTS, and the reason first written here was WRONG.
 *
 * Under CONFIG_GENDWARFKSYMS the fingerprint of an exported symbol is hashed
 * from the DWARF of the object carrying the EXPORT_SYMBOL. When the body moves
 * to Rust and the EXPORT_SYMBOL stays in a C file, the fingerprint moves.
 * Measured on lib/bcd.c: _bcd2bin 0x605be21c -> 0xcf47c3a6.
 *
 * THIS FILE USED TO SAY THAT WAS BECAUSE RUST SPELLS `u8` WHERE C SPELLS
 * `unsigned char`. It is not. Compare the two strings for any such symbol --
 * `gendwarfksyms --dump-versions` with and without --stable -- and the types
 * are identical, and C's. The Rust does not enter this hash at all.
 *
 * The difference is the PARAMETER NAMES. With no C definition in the
 * translation unit, the only DWARF describing the symbol is what
 * include/linux/export.h:69 plants beside the EXPORT_SYMBOL:
 *
 *	static typeof(sym) *__gendwarfksyms_ptr_##sym = &sym;
 *
 * A pointer-to-function yields a DW_TAG_subroutine_type, which has parameter
 * types but no parameter names -- a type has no names in it. gendwarfksyms
 * hashes parameter names when it has them, so losing them moves the CRC.
 *
 * Believing the wrong cause made the fix ten times too broad, and harmful: 29
 * pins were added for TYPES on the theory that Rust spelled them differently.
 * A type pin freezes that type's LAYOUT, so a real ABI break inside it (struct
 * chacha_state 64 -> 128 bytes) stops moving the CRC. They hid what the
 * fingerprint exists to show. Pin symbols, never types.
 *
 * THE PREFERRED MECHANISM IS NO LONGER THIS HEADER. rust/kernel/kabi.rs's
 * kabi_export!() puts the export AND the contract in the Rust object, so the
 * C file can be deleted rather than kept alive to hold a pin -- and there the
 * Rust IS what gets hashed, so the C-versus-Rust type spelling finally does
 * matter. This header remains for ports that still keep a C entry because it
 * does real work: a guard, a static-key dispatch, a WARN_ON.
 *
 * KABI_TYPE_STRING() pins the hashed string to the one the C definition
 * produced, restoring the fingerprint exactly.
 *
 * THE RULES ARE BUILD-TIME METADATA AND NEVER REACH THE KERNEL. They live in
 * a .discard section that the linker drops -- verified: zero occurrences in
 * vmlinux -- and are read by scripts/gendwarfksyms, a host tool. No codegen
 * changes, not one instruction differs. A wrong pin can misreport the ABI; it
 * cannot break the kernel.
 *
 * TWO THINGS THAT WILL BITE YOU.
 *
 * 1. The rules are IGNORED unless gendwarfksyms is passed --stable, which is
 *    not a Kconfig symbol: scripts/Makefile.build only passes it when
 *    KBUILD_GENDWARFKSYMS_STABLE is set. Forgetting it does not fail the
 *    build, it silently changes the module ABI. kbuild-env.sh sets it.
 *
 * 2. A PIN IS A LITERAL, so a pin becomes a lie the moment the C declaration
 *    changes -- it would keep asserting the old fingerprint and hide a real ABI
 *    break. Never hand-write one: rig/kabi-pin.sh --capture generates them from
 *    the C definition BEFORE the thunk is deleted, and --check re-derives their
 *    types from the header and fails on drift.
 *
 * Adapted from scripts/gendwarfksyms/examples/kabi.h, which is an example
 * rather than a shipped header.
 */
#ifndef _LINUX_KABI_H
#define _LINUX_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>

#define ___KABI_RULE(hint, target, value)				\
	static const char __PASTE(__gendwarfksyms_rule_,		\
				  __COUNTER__)[] __used __aligned(1)	\
		__section(".discard.gendwarfksyms.kabi_rules") =	\
			"1\0" #hint "\0" target "\0" value

/*
 * KABI_TYPE_STRING(symbol, str)
 *   Hash str for symbol instead of the type string its real definition
 *   produces. Both arguments are string literals.
 */
#define KABI_TYPE_STRING(symbol, str) ___KABI_RULE(type_string, symbol, str)

#endif /* _LINUX_KABI_H */
