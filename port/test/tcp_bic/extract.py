#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the tunables, struct bictcp and the three arithmetic pieces of the PRISTINE tcp_bic.c (C side), or of tcp_bic_glue.c (Rust side: the wrappers), as a standalone C file with the entry points bic_update(), bic_ssthresh() and bic_acked()."""
import sys
s = open(sys.argv[1]).read()
head = s[s.index("#define BICTCP_BETA_SCALE"):s.index("module_param(fast_convergence")]
a = s.index("/* BIC TCP Parameters */"); head += s[a:s.index("static inline void bictcp_reset")]
if "RUST-WRAPPERS BEGIN" in s:
    body = s[s.index("/* RUST-WRAPPERS BEGIN"):s.index("/* RUST-WRAPPERS END */")]
    body += "static u32 bic_ssthresh(struct bictcp *ca, u32 cwnd) { return rust_bic_ssthresh(ca, cwnd, fast_convergence, beta, low_window); }\n"
    body += "static void bic_acked(struct bictcp *ca, u32 pk) { rust_bic_acked(ca, pk); }\n"
else:
    a = s.index("static inline void bictcp_update("); b = s.index("static void bictcp_cong_avoid(")
    body = s[a:b]
    a = s.index("\tca->epoch_start = 0;\t/* end of epoch */"); b = s.index("static void bictcp_state(")
    r = s[a:b].rstrip().rstrip("}").replace("tcp_snd_cwnd(tp)", "cwnd")
    body += "static u32 bic_ssthresh(struct bictcp *ca, u32 cwnd)\n{\n" + r + "}\n"
    old = "\t\tca->delayed_ack += sample->pkts_acked -\n\t\t\t(ca->delayed_ack >> ACK_RATIO_SHIFT);\n"
    assert old in s
    body += "static void bic_acked(struct bictcp *ca, u32 pk)\n{\n" + old.replace("sample->pkts_acked", "pk") + "}\n"
body += "static void bic_update(struct bictcp *ca, u32 cwnd) { bictcp_update(ca, cwnd); }\n"
open(sys.argv[2], "w").write('#include "refshim.h"\n' + head + body)
