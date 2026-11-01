#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- kernel/sched/loadavg.c as the glue: upstream without fixed_power_int() and calc_load_n() (they are in loadavg_rs.rs). Without CONFIG_RUST the file includes upstream's body,
installed byte-identical as loadavg_norust.c."""
import sys
s = open(sys.argv[1]).read()
a = s.index("/**\n * fixed_power_int"); b = s.index("#ifdef CONFIG_NO_HZ_COMMON", a)
# keep the long comment above calc_load_n? it is documentation of the removed function; drop everything between
s = s[:a] + "/* fixed_power_int() and calc_load_n() are in loadavg_rs.rs (declared in <linux/sched/loadavg.h>). */\nstatic_assert(FSHIFT == 11 && FIXED_1 == 2048);\n\n" + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0\n/*\n * RUST PORT (kernel/sched/loadavg.c, 6.18.49): fixed_power_int() and calc_load_n() are in loadavg_rs.rs; this file (included by build_utility.c) keeps the rest. Without\n * CONFIG_RUST upstream's whole file, installed byte-identical as loadavg_norust.c, is used instead.\n */\n#ifndef CONFIG_RUST\n#include \"loadavg_norust.c\"\n#else\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0\n", note, 1) + "\n#endif /* CONFIG_RUST */\n"
open(sys.argv[2], "w").write(s)
