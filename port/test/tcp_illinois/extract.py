#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the tunables, struct illinois and the functions rtt_reset .. tcp_illinois_ssthresh of the PRISTINE tcp_illinois.c (C side), or of tcp_illinois_glue.c (Rust side: the same functions with the wrappers), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
head = s[s.index("#define ALPHA_SHIFT"):s.index("static void rtt_reset(")]
sock = r'''
struct illinois;
struct sock { struct tcp_sock tp; struct illinois ca; };
extern int cwnd_limited;
#define tcp_sk(sk) (&(sk)->tp)
#define inet_csk_ca(sk) (&(sk)->ca)
#define tcp_snd_cwnd(tp) ((tp)->snd_cwnd)
#define tcp_snd_cwnd_set(tp, v) ((tp)->snd_cwnd = (v))
#define tcp_is_cwnd_limited(sk) (cwnd_limited)
#define tcp_in_slow_start(tp) ((tp)->snd_cwnd < (tp)->snd_ssthresh)
static u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
	acked -= cwnd - tp->snd_cwnd; tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp); return acked;
}
'''
body = s[s.index("static void rtt_reset("):s.index("/* Extract info for Tcp socket info")]
i = head.index("struct illinois {")
open(sys.argv[2], "w").write('#include "refshim.h"\n' + head[:i] + head[i:] + sock + body)
