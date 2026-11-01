#!/usr/bin/env python3
"""extract.py SOURCE.c OUT.c -- the tunables, struct htcp and the functions htcp_cong_time .. htcp_state of the PRISTINE tcp_htcp.c (C side), or of tcp_htcp_glue.c (Rust side: the same functions with the wrappers), as a standalone C file."""
import sys
s = open(sys.argv[1]).read()
head = s[s.index("#define ALPHA_BASE"):s.index("static inline u32 htcp_cong_time(")]
sock = r'''
struct sock { struct tcp_sock tp; struct inet_connection_sock icsk; struct htcp ca; };
extern int cwnd_limited;
#define tcp_sk(sk) (&(sk)->tp)
#define inet_csk(sk) (&(sk)->icsk)
#define inet_csk_ca(sk) (&(sk)->ca)
#define tcp_snd_cwnd(tp) ((tp)->snd_cwnd)
#define tcp_snd_cwnd_set(tp, v) ((tp)->snd_cwnd = (v))
#define tcp_is_cwnd_limited(sk) (cwnd_limited)
#define tcp_in_slow_start(tp) ((tp)->snd_cwnd < (tp)->snd_ssthresh)
static u32 tcp_reno_undo_cwnd(struct sock *sk) { return max(sk->tp.snd_cwnd, sk->tp.snd_ssthresh >> 1); }
static u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
	acked -= cwnd - tp->snd_cwnd; tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp); return acked;
}
'''
body = s[s.index("static inline u32 htcp_cong_time("):s.index("static struct tcp_congestion_ops htcp")]
open(sys.argv[2], "w").write('#include "refshim.h"\n' + head + sock + body)
