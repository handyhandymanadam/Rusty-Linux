/* SPDX-License-Identifier: GPL-2.0-only */
/* <linux/init.h>, reduced to the section attributes.
 *
 * THE SECTION ATTRIBUTES ARE DROPPED HERE, DELIBERATELY, AND THAT IS THE ONE
 * THING THIS HARNESS DOES NOT TEST. There is no .init.text in a userspace
 * program, and forcing one would only move code around in an ELF nobody
 * boots. Section placement is checked separately and mechanically instead:
 * run.sh reads `objdump -h` on BOTH the Rust object built with the kernel's
 * own flags and the C object built with __init expanded to a real section
 * attribute, and requires .text empty and .init.text non-empty on each. So
 * the differential answers "does it compute the same thing" and objdump
 * answers "does it land in the same section"; neither is asked to do the
 * other's job. */
#ifndef _SHIM_FW_TABLE_LINUX_INIT_H
#define _SHIM_FW_TABLE_LINUX_INIT_H

/* Guarded, so run.sh's section-placement build can supply the real thing on
 * the command line. Defining it unconditionally silently won that argument
 * once, and the placement check correctly refused to report a comparison it
 * had not made. */
#ifndef __init
#define __init
#endif
#ifndef __initdata
#define __initdata
#endif
#ifndef __ref
#define __ref
#endif

#endif
