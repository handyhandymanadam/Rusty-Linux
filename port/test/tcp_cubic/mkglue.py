#!/usr/bin/env python3
"""mkglue.py PRISTINE.c OUT.c -- tcp_cubic_glue.c = upstream net/ipv4/tcp_cubic.c with cubic_root() and bictcp_update() replaced by thin wrappers over tcp_cubic_rs.rs."""
import sys
s = open(sys.argv[1]).read()
wr = r'''/* RUST-WRAPPERS BEGIN: the arithmetic is in tcp_cubic_rs.rs. */
u32 rust_cubic_root(u64 a);
void rust_bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked, u32 now, u32 hz, u64 delay_jiffies, int tcp_friendliness, u32 cube_rtt_scale, u32 beta_scale, u64 cube_factor);

/* tcp_cubic_rs.rs hard-codes these offsets of struct bictcp. */
static_assert(offsetof(struct bictcp, cnt) == 0 && offsetof(struct bictcp, last_max_cwnd) == 4 && offsetof(struct bictcp, last_cwnd) == 8 && offsetof(struct bictcp, last_time) == 12 &&
	      offsetof(struct bictcp, bic_origin_point) == 16 && offsetof(struct bictcp, bic_K) == 20 && offsetof(struct bictcp, delay_min) == 24 && offsetof(struct bictcp, epoch_start) == 28 &&
	      offsetof(struct bictcp, ack_cnt) == 32 && offsetof(struct bictcp, tcp_cwnd) == 36);
static_assert(BICTCP_HZ == 10);

static u32 __maybe_unused cubic_root(u64 a)
{
	return rust_cubic_root(a);
}

static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	rust_bictcp_update(ca, cwnd, acked, tcp_jiffies32, HZ, usecs_to_jiffies(ca->delay_min), tcp_friendliness, cube_rtt_scale, beta_scale, cube_factor);
}
/* RUST-WRAPPERS END */

'''
a = s.index("static u32 cubic_root(u64 a)"); b = s.index("__bpf_kfunc static void cubictcp_cong_avoid(")
s = s[:a] + wr + s[b:]
note = "// SPDX-License-Identifier: GPL-2.0-only\n/*\n * RUST PORT (net/ipv4/tcp_cubic.c, 6.18.49): cubic_root() and bictcp_update() are in tcp_cubic_rs.rs, called through the wrappers below. Everything that touches the socket,\n * HyStart, the module parameters and the registration are upstream's. Upstream's whole file is installed as tcp_cubic_norust.c for CONFIG_RUST=n.\n */\n"
s = s.replace("// SPDX-License-Identifier: GPL-2.0-only\n", note, 1)
open(sys.argv[2], "w").write(s)
