/* SPDX-License-Identifier: GPL-2.0-only */
/* <linux/acpi.h>, reduced to what lib/fw_table.c actually takes from it.
 *
 * The real header pulls in acpi_bus.h, acpi_drivers.h, acpi_io.h and
 * asm/acpi.h -- the whole ACPI subsystem. lib/fw_table.c needs exactly two
 * things out of all that: the ACPICA table structure definitions, and the
 * EXPORT_SYMBOL_ACPI_LIB / __init_or_acpilib pair.
 *
 * THE STRUCTURE DEFINITIONS ARE UPSTREAM'S OWN, NOT TRANSCRIBED. This
 * includes port/pristine/include/acpi/{actypes,actbl}.h verbatim, and
 * actbl.h pulls actbl1/2/3.h itself. Transcribing them would put the
 * oracle's field offsets in this file's author's hands, which is the one
 * thing that must not happen: every offset the port reads is checked against
 * offsetof() on THESE definitions in drv.c's geometry stage, and that check
 * is worth nothing if both sides came from the same pen.
 *
 * The two defines below are set to the values config-full resolves them to,
 * which is the whole reason this file's port has no exports and lives in
 * .init.text -- see fw_table_rs.rs's module docs for the derivation and
 * logs/build-limits.md for the entry. CONFIG_ACPI_TABLE_LIB is unset in both
 * of this project's configs, so EXPORT_SYMBOL_ACPI_LIB expands to nothing;
 * __init_or_acpilib would be __init, and <linux/init.h>'s shim explains why
 * that is dropped here and checked with objdump instead. */
#ifndef _SHIM_FW_TABLE_LINUX_ACPI_H
#define _SHIM_FW_TABLE_LINUX_ACPI_H

/* aclinux.h:31 for an in-kernel build. Without it actypes.h defines its own
 * u8/u16/u64 from COMPILER_DEPENDENT_* and the ACPICA structs would be laid
 * out from types the kernel does not use. */
#define ACPI_USE_SYSTEM_INTTYPES
/* aclinux.h:107, ACPI_MACHINE_WIDTH = BITS_PER_LONG. */
#define ACPI_MACHINE_WIDTH 64
/* acenv.h's default: an empty calling-convention marker on anything but
 * 16-bit DOS. actypes.h uses it in two typedefs this file never calls. */
#define ACPI_SYSTEM_XFACE

/* CRITERION 8 (logs/floor.md RAISE 3), and it bit on the first compile.
 *
 * fw_table.h:52 forks on `IS_ENABLED(CONFIG_ACPI) && !IS_ENABLED(CONFIG_CXL_BUS)`.
 * Without this define both operands are 0 in the preprocessor and the oracle
 * silently took the #else arm -- the "CXL" namespace export, the arm
 * config-full does NOT build. The oracle would have been a different program
 * from the kernel's, agreeing with the port for the wrong reason.
 *
 * config-full has CONFIG_ACPI=y, CONFIG_CXL_BUS unset, CONFIG_ACPI_TABLE_LIB
 * unset. CONFIG_CXL_BUS and CONFIG_ACPI_TABLE_LIB are therefore left
 * undefined here, which is what "unset" means to the preprocessor.
 * run.sh checks the resulting arm mechanically rather than trusting this
 * comment. */
#define CONFIG_ACPI 1

#include <linux/types.h>
#include <acpi/actypes.h>
#include <acpi/actbl.h>

/* acpi.h:42-49, reproduced as the FORK IT IS rather than as its answer.
 *
 * Writing `#define EXPORT_SYMBOL_ACPI_LIB(x)` unconditionally would give the
 * right result for config-full and make run.sh's criterion-8 check blind to
 * the second level of the macro chain: a build that turned
 * CONFIG_ACPI_TABLE_LIB on would still expand to nothing and the check would
 * still pass. Written this way, it would expand to an undefined
 * EXPORT_SYMBOL_NS_GPL and the check fires. Found by adversarial review,
 * 2026-09-05.
 *
 * There is deliberately NO shim for <linux/export.h>. One existed, defined
 * EXPORT_SYMBOL_NS_GPL to nothing, and was included by nothing -- so it was
 * dead weight that would have silently disarmed the check the day something
 * pulled it in. Same review.
 *
 * __init_or_acpilib is GUARDED because it, not __init, is what
 * lib/fw_table.c's functions actually carry (via fw_table.h:55's
 * `#define __init_or_fwtbl_lib __init_or_acpilib`). run.sh's
 * section-placement build supplies the real section attribute on the command
 * line; the first version of that check overrode __init instead, changed
 * nothing, and the check correctly refused to report a comparison it had not
 * made. */
#ifdef CONFIG_ACPI_TABLE_LIB
#define EXPORT_SYMBOL_ACPI_LIB(x) EXPORT_SYMBOL_NS_GPL(x, "ACPI")
#ifndef __init_or_acpilib
#define __init_or_acpilib
#endif
#else
#define EXPORT_SYMBOL_ACPI_LIB(x)
#ifndef __init_or_acpilib
#define __init_or_acpilib __init
#endif
#endif
#define __initdata_or_acpilib

#endif
