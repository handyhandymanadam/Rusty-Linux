#!/usr/bin/env python3
"""extract_ref.py PRISTINE ntp.c OUT.c OUT_STRUCT.h -- the discipline arithmetic (CONFIG_NTP_PPS=n) of the PRISTINE kernel/time/ntp.c as a standalone reference."""
import sys
s = open(sys.argv[1]).read()
def fn(sig):
    i = s.index(sig); j = s.index("\n}\n", i) + 3
    return s[i:j]
a = s.index("struct ntp_data {"); b = s.index("\n};\n", a) + 4
struct = s[a:b]
c = s.index("#else /* !CONFIG_NTP_PPS */") + len("#else /* !CONFIG_NTP_PPS */")
d = s.index("#endif /* CONFIG_NTP_PPS */", c)
stubs = s[c:d]
consts = s[s.index("#define SECS_PER_DAY"):s.index("#ifdef CONFIG_NTP_PPS\n\n/*")]
parts = [consts, stubs, fn("static void ntp_update_frequency("), fn("static inline s64 ntp_update_offset_fll("), fn("static void ntp_update_offset("), fn("static void __ntp_clear("),
         fn("ktime_t ntp_get_next_leap("), fn("int second_overflow("), fn("static inline void process_adj_status("), fn("static inline void process_adjtimex_modes("), fn("int ntp_adjtimex(")]
open(sys.argv[3], "w").write(struct)
open(sys.argv[2], "w").write('#include "refshim.h"\n#include "ntpstruct.h"\nstatic struct ntp_data tk_ntp_data[TIMEKEEPERS_MAX];\n' + "\n".join(parts) + '''
struct ntp_data *ref_data(int id) { return &tk_ntp_data[id]; }
''')
