// SPDX-License-Identifier: GPL-2.0-only
/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Implementation of the Transmission Control Protocol(TCP).
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Mark Evans, <evansmp@uhura.aston.ac.uk>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Florian La Roche, <flla@stud.uni-sb.de>
 *		Charles Hedrick, <hedrick@klinzhai.rutgers.edu>
 *		Linus Torvalds, <torvalds@cs.helsinki.fi>
 *		Alan Cox, <gw4pts@gw4pts.ampr.org>
 *		Matthew Dillon, <dillon@apollo.west.oic.com>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 */

/*
 * Changes:	Pedro Roque	:	Retransmit queue handled by TCP.
 *				:	Fragmentation on mtu decrease
 *				:	Segment collapse on retransmit
 *				:	AF independence
 *
 *		Linus Torvalds	:	send_delayed_ack
 *		David S. Miller	:	Charge memory using the right skb
 *					during syn/ack processing.
 *		David S. Miller :	Output engine completely rewritten.
 *		Andrea Arcangeli:	SYNACK carry ts_recent in tsecr.
 *		Cacophonix Gaul :	draft-minshall-nagle-01
 *		J Hadi Salim	:	ECN support
 *
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/compiler.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/static_key.h>

#include <trace/events/tcp.h>

/* Refresh clocks of a TCP socket,
 * ensuring monotically increasing values.
 */
void tcp_mstamp_refresh(struct tcp_sock *tp)
{
	u64 val = tcp_clock_ns();

	tp->tcp_clock_cache = val;
	tp->tcp_mstamp = div_u64(val, NSEC_PER_USEC);
}

static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp);

/* Account for new data that has been sent to the network. */
static void tcp_event_new_data_sent(struct sock *sk, struct sk_buff *skb)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int prior_packets = tp->packets_out;

	WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(skb)->end_seq);

	__skb_unlink(skb, &sk->sk_write_queue);
	tcp_rbtree_insert(&sk->tcp_rtx_queue, skb);

	if (tp->highest_sack == NULL)
		tp->highest_sack = skb;

	tp->packets_out += tcp_skb_pcount(skb);
	if (!prior_packets || icsk->icsk_pending == ICSK_TIME_LOSS_PROBE)
		tcp_rearm_rto(sk);

	NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT,
		      tcp_skb_pcount(skb));
}

/* SND.NXT, if window was not shrunk or the amount of shrunk was less than one
 * window scaling factor due to loss of precision.
 * If window has been shrunk, what should we make? It is not clear at all.
 * Using SND.UNA we will fail to open window, SND.NXT is out of window. :-(
 * Anything in between SND.UNA...SND.UNA+SND.WND also can be already
 * invalid. OK, let's make this for now:
 */
static inline __u32 tcp_acceptable_seq(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (!before(tcp_wnd_end(tp), tp->snd_nxt) ||
	    (tp->rx_opt.wscale_ok &&
	     ((tp->snd_nxt - tcp_wnd_end(tp)) < (1 << tp->rx_opt.rcv_wscale))))
		return tp->snd_nxt;
	else
		return tcp_wnd_end(tp);
}

/* Calculate mss to advertise in SYN segment.
 * RFC1122, RFC1063, draft-ietf-tcpimpl-pmtud-01 state that:
 *
 * 1. It is independent of path mtu.
 * 2. Ideally, it is maximal possible segment size i.e. 65535-40.
 * 3. For IPv4 it is reasonable to calculate it from maximal MTU of
 *    attached devices, because some buggy hosts are confused by
 *    large MSS.
 * 4. We do not make 3, we advertise MSS, calculated from first
 *    hop device mtu, but allow to raise it to ip_rt_min_advmss.
 *    This may be overridden via information stored in routing table.
 * 5. Value 65535 for MSS is valid in IPv6 and means "as large as possible,
 *    probably even Jumbo".
 */
static __u16 tcp_advertise_mss(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	int mss = tp->advmss;

	if (dst) {
		unsigned int metric = dst_metric_advmss(dst);

		if (metric < mss) {
			mss = metric;
			tp->advmss = mss;
		}
	}

	return (__u16)mss;
}

/* RFC2861. Reset CWND after idle period longer RTO to "restart window".
 * This is the first part of cwnd validation mechanism.
 */
void tcp_cwnd_restart(struct sock *sk, s32 delta)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 restart_cwnd = tcp_init_cwnd(tp, __sk_dst_get(sk));
	u32 cwnd = tp->snd_cwnd;

	tcp_ca_event(sk, CA_EVENT_CWND_RESTART);

	tp->snd_ssthresh = tcp_current_ssthresh(sk);
	restart_cwnd = min(restart_cwnd, cwnd);

	while ((delta -= inet_csk(sk)->icsk_rto) > 0 && cwnd > restart_cwnd)
		cwnd >>= 1;
	tp->snd_cwnd = max(cwnd, restart_cwnd);
	tp->snd_cwnd_stamp = tcp_jiffies32;
	tp->snd_cwnd_used = 0;
}

/* Congestion state accounting after a packet has been sent. */
static void tcp_event_data_sent(struct tcp_sock *tp,
				struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const u32 now = tcp_jiffies32;

	if (tcp_packets_in_flight(tp) == 0)
		tcp_ca_event(sk, CA_EVENT_TX_START);

	/* If this is the first data packet sent in response to the
	 * previous received data,
	 * and it is a reply for ato after last received packet,
	 * increase pingpong count.
	 */
	if (before(tp->lsndtime, icsk->icsk_ack.lrcvtime) &&
	    (u32)(now - icsk->icsk_ack.lrcvtime) < icsk->icsk_ack.ato)
		inet_csk_inc_pingpong_cnt(sk);

	tp->lsndtime = now;
}

/* Account for an ACK we sent. */
static inline void tcp_event_ack_sent(struct sock *sk, unsigned int pkts,
				      u32 rcv_nxt)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (unlikely(tp->compressed_ack > TCP_FASTRETRANS_THRESH)) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPACKCOMPRESSED,
			      tp->compressed_ack - TCP_FASTRETRANS_THRESH);
		tp->compressed_ack = TCP_FASTRETRANS_THRESH;
		if (hrtimer_try_to_cancel(&tp->compressed_ack_timer) == 1)
			__sock_put(sk);
	}

	if (unlikely(rcv_nxt != tp->rcv_nxt))
		return;  /* Special ACK sent by DCTCP to reflect ECN */
	tcp_dec_quickack_mode(sk, pkts);
	inet_csk_clear_xmit_timer(sk, ICSK_TIME_DACK);
}

/* Determine a window scaling and initial window to offer.
 * Based on the assumption that the given amount of space
 * will be offered. Store the results in the tp structure.
 * NOTE: for smooth operation initial space offering should
 * be a multiple of mss if possible. We assume here that mss >= 1.
 * This MUST be enforced by all callers.
 */
void tcp_select_initial_window(const struct sock *sk, int __space, __u32 mss,
			       __u32 *rcv_wnd, __u32 *window_clamp,
			       int wscale_ok, __u8 *rcv_wscale,
			       __u32 init_rcv_wnd)
{
	unsigned int space = (__space < 0 ? 0 : __space);

	/* If no clamp set the clamp to the max possible scaled window */
	if (*window_clamp == 0)
		(*window_clamp) = (U16_MAX << TCP_MAX_WSCALE);
	space = min(*window_clamp, space);

	/* Quantize space offering to a multiple of mss if possible. */
	if (space > mss)
		space = rounddown(space, mss);

	/* NOTE: offering an initial window larger than 32767
	 * will break some buggy TCP stacks. If the admin tells us
	 * it is likely we could be speaking with such a buggy stack
	 * we will truncate our initial window offering to 32K-1
	 * unless the remote has sent us a window scaling option,
	 * which we interpret as a sign the remote TCP is not
	 * misinterpreting the window field as a signed quantity.
	 */
	if (sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		(*rcv_wnd) = min(space, MAX_TCP_WINDOW);
	else
		(*rcv_wnd) = min_t(u32, space, U16_MAX);

	if (init_rcv_wnd)
		*rcv_wnd = min(*rcv_wnd, init_rcv_wnd * mss);

	*rcv_wscale = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window */
		space = max_t(u32, space, sock_net(sk)->ipv4.sysctl_tcp_rmem[2]);
		space = max_t(u32, space, sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		*rcv_wscale = clamp_t(int, ilog2(space) - 15,
				      0, TCP_MAX_WSCALE);
	}
	/* Set the clamp no higher than max representable value */
	(*window_clamp) = min_t(__u32, U16_MAX << (*rcv_wscale), *window_clamp);
}
EXPORT_SYMBOL(tcp_select_initial_window);

/* Chose a new window to advertise, update state in tcp_sock for the
 * socket, and return result with RFC1323 scaling applied.  The return
 * value can be stuffed directly into th->window for an outgoing
 * frame.
 */
static u16 tcp_select_window(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 old_win = tp->rcv_wnd;
	u32 cur_win = tcp_receive_window(tp);
	u32 new_win = __tcp_select_window(sk);

	/* Never shrink the offered window */
	if (new_win < cur_win) {
		/* Danger Will Robinson!
		 * Don't update rcv_wup/rcv_wnd here or else
		 * we will not be able to advertise a zero
		 * window in time.  --DaveM
		 *
		 * Relax Will Robinson.
		 */
		if (new_win == 0)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPWANTZEROWINDOWADV);
		new_win = ALIGN(cur_win, 1 << tp->rx_opt.rcv_wscale);
	}
	tp->rcv_wnd = new_win;
	tp->rcv_wup = tp->rcv_nxt;

	/* Make sure we do not exceed the maximum possible
	 * scaled window.
	 */
	if (!tp->rx_opt.rcv_wscale &&
	    sock_net(sk)->ipv4.sysctl_tcp_workaround_signed_windows)
		new_win = min(new_win, MAX_TCP_WINDOW);
	else
		new_win = min(new_win, (65535U << tp->rx_opt.rcv_wscale));

	/* RFC1323 scaling applied */
	new_win >>= tp->rx_opt.rcv_wscale;

	/* If we advertise zero window, disable fast path. */
	if (new_win == 0) {
		tp->pred_flags = 0;
		if (old_win)
			NET_INC_STATS(sock_net(sk),
				      LINUX_MIB_TCPTOZEROWINDOWADV);
	} else if (old_win == 0) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPFROMZEROWINDOWADV);
	}

	return new_win;
}

/* Packet ECN state for a SYN-ACK */
static void tcp_ecn_send_synack(struct sock *sk, struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_CWR;
	if (!(tp->ecn_flags & TCP_ECN_OK))
		TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_ECE;
	else if (tcp_ca_needs_ecn(sk) ||
		 tcp_bpf_ca_needs_ecn(sk))
		INET_ECN_xmit(sk);
}

/* Packet ECN state for a SYN.  */
static void tcp_ecn_send_syn(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool bpf_needs_ecn = tcp_bpf_ca_needs_ecn(sk);
	bool use_ecn = sock_net(sk)->ipv4.sysctl_tcp_ecn == 1 ||
		tcp_ca_needs_ecn(sk) || bpf_needs_ecn;

	if (!use_ecn) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_feature(dst, RTAX_FEATURE_ECN))
			use_ecn = true;
	}

	tp->ecn_flags = 0;

	if (use_ecn) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ECE | TCPHDR_CWR;
		tp->ecn_flags = TCP_ECN_OK;
		if (tcp_ca_needs_ecn(sk) || bpf_needs_ecn)
			INET_ECN_xmit(sk);
	}
}

static void tcp_ecn_clear_syn(struct sock *sk, struct sk_buff *skb)
{
	if (sock_net(sk)->ipv4.sysctl_tcp_ecn_fallback)
		/* tp->ecn_flags are cleared at a later point in time when
		 * SYN ACK is ultimatively being received.
		 */
		TCP_SKB_CB(skb)->tcp_flags &= ~(TCPHDR_ECE | TCPHDR_CWR);
}

static void
tcp_ecn_make_synack(const struct request_sock *req, struct tcphdr *th)
{
	if (inet_rsk(req)->ecn_ok)
		th->ece = 1;
}

/* Set up ECN state for a packet on a ESTABLISHED socket that is about to
 * be sent.
 */
static void tcp_ecn_send(struct sock *sk, struct sk_buff *skb,
			 struct tcphdr *th, int tcp_header_len)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tp->ecn_flags & TCP_ECN_OK) {
		/* Not-retransmitted data segment: set ECT and inject CWR. */
		if (skb->len != tcp_header_len &&
		    !before(TCP_SKB_CB(skb)->seq, tp->snd_nxt)) {
			INET_ECN_xmit(sk);
			if (tp->ecn_flags & TCP_ECN_QUEUE_CWR) {
				tp->ecn_flags &= ~TCP_ECN_QUEUE_CWR;
				th->cwr = 1;
				skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;
			}
		} else if (!tcp_ca_needs_ecn(sk)) {
			/* ACK or retransmitted segment: clear ECT|CE */
			INET_ECN_dontxmit(sk);
		}
		if (tp->ecn_flags & TCP_ECN_DEMAND_CWR)
			th->ece = 1;
	}
}

/* Constructs common control bits of non-data skb. If SYN/FIN is present,
 * auto increment end seqno.
 */
static void tcp_init_nondata_skb(struct sk_buff *skb, u32 seq, u8 flags)
{
	skb->ip_summed = CHECKSUM_PARTIAL;

	TCP_SKB_CB(skb)->tcp_flags = flags;
	TCP_SKB_CB(skb)->sacked = 0;

	tcp_skb_pcount_set(skb, 1);

	TCP_SKB_CB(skb)->seq = seq;
	if (flags & (TCPHDR_SYN | TCPHDR_FIN))
		seq++;
	TCP_SKB_CB(skb)->end_seq = seq;
}

static inline bool tcp_urg_mode(const struct tcp_sock *tp)
{
	return tp->snd_una != tp->snd_up;
}

#define OPTION_SACK_ADVERTISE	(1 << 0)
#define OPTION_TS		(1 << 1)
#define OPTION_MD5		(1 << 2)
#define OPTION_WSCALE		(1 << 3)
#define OPTION_FAST_OPEN_COOKIE	(1 << 8)
#define OPTION_SMC		(1 << 9)
#define OPTION_MPTCP		(1 << 10)

static void smc_options_write(__be32 *ptr, u16 *options)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (unlikely(OPTION_SMC & *options)) {
			*ptr++ = htonl((TCPOPT_NOP  << 24) |
				       (TCPOPT_NOP  << 16) |
				       (TCPOPT_EXP <<  8) |
				       (TCPOLEN_EXP_SMC_BASE));
			*ptr++ = htonl(TCPOPT_SMC_MAGIC);
		}
	}
#endif
}

struct tcp_out_options {
	u16 options;		/* bit field of OPTION_* */
	u16 mss;		/* 0 to disable */
	u8 ws;			/* window scale, 0 to disable */
	u8 num_sack_blocks;	/* number of SACK blocks to include */
	u8 hash_size;		/* bytes in hash_location */
	__u8 *hash_location;	/* temporary pointer, overloaded */
	__u32 tsval, tsecr;	/* need to include OPTION_TS */
	struct tcp_fastopen_cookie *fastopen_cookie;	/* Fast open cookie */
	struct mptcp_out_options mptcp;
};

static void mptcp_options_write(__be32 *ptr, struct tcp_out_options *opts)
{
#if IS_ENABLED(CONFIG_MPTCP)
	if (unlikely(OPTION_MPTCP & opts->options))
		mptcp_write_options(ptr, &opts->mptcp);
#endif
}

/* Write previously computed TCP options to the packet.
 *
 * Beware: Something in the Internet is very sensitive to the ordering of
 * TCP options, we learned this through the hard way, so be careful here.
 * Luckily we can at least blame others for their non-compliance but from
 * inter-operability perspective it seems that we're somewhat stuck with
 * the ordering which we have been using if we want to keep working with
 * those broken things (not that it currently hurts anybody as there isn't
 * particular reason why the ordering would need to be changed).
 *
 * At least SACK_PERM as the first option is known to lead to a disaster
 * (but it may well be that other scenarios fail similarly).
 */
static void tcp_options_write(__be32 *ptr, struct tcp_sock *tp,
			      struct tcp_out_options *opts)
{
	u16 options = opts->options;	/* mungable copy */

	if (unlikely(OPTION_MD5 & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
			       (TCPOPT_MD5SIG << 8) | TCPOLEN_MD5SIG);
		/* overload cookie hash location */
		opts->hash_location = (__u8 *)ptr;
		ptr += 4;
	}

	if (unlikely(opts->mss)) {
		*ptr++ = htonl((TCPOPT_MSS << 24) |
			       (TCPOLEN_MSS << 16) |
			       opts->mss);
	}

	if (likely(OPTION_TS & options)) {
		if (unlikely(OPTION_SACK_ADVERTISE & options)) {
			*ptr++ = htonl((TCPOPT_SACK_PERM << 24) |
				       (TCPOLEN_SACK_PERM << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
			options &= ~OPTION_SACK_ADVERTISE;
		} else {
			*ptr++ = htonl((TCPOPT_NOP << 24) |
				       (TCPOPT_NOP << 16) |
				       (TCPOPT_TIMESTAMP << 8) |
				       TCPOLEN_TIMESTAMP);
		}
		*ptr++ = htonl(opts->tsval);
		*ptr++ = htonl(opts->tsecr);
	}

	if (unlikely(OPTION_SACK_ADVERTISE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_NOP << 16) |
			       (TCPOPT_SACK_PERM << 8) |
			       TCPOLEN_SACK_PERM);
	}

	if (unlikely(OPTION_WSCALE & options)) {
		*ptr++ = htonl((TCPOPT_NOP << 24) |
			       (TCPOPT_WINDOW << 16) |
			       (TCPOLEN_WINDOW << 8) |
			       opts->ws);
	}

	if (unlikely(opts->num_sack_blocks)) {
		struct tcp_sack_block *sp = tp->rx_opt.dsack ?
			tp->duplicate_sack : tp->selective_acks;
		int this_sack;

		*ptr++ = htonl((TCPOPT_NOP  << 24) |
			       (TCPOPT_NOP  << 16) |
			       (TCPOPT_SACK <<  8) |
			       (TCPOLEN_SACK_BASE + (opts->num_sack_blocks *
						     TCPOLEN_SACK_PERBLOCK)));

		for (this_sack = 0; this_sack < opts->num_sack_blocks;
		     ++this_sack) {
			*ptr++ = htonl(sp[this_sack].start_seq);
			*ptr++ = htonl(sp[this_sack].end_seq);
		}

		tp->rx_opt.dsack = 0;
	}

	if (unlikely(OPTION_FAST_OPEN_COOKIE & options)) {
		struct tcp_fastopen_cookie *foc = opts->fastopen_cookie;
		u8 *p = (u8 *)ptr;
		u32 len; /* Fast Open option length */

		if (foc->exp) {
			len = TCPOLEN_EXP_FASTOPEN_BASE + foc->len;
			*ptr = htonl((TCPOPT_EXP << 24) | (len << 16) |
				     TCPOPT_FASTOPEN_MAGIC);
			p += TCPOLEN_EXP_FASTOPEN_BASE;
		} else {
			len = TCPOLEN_FASTOPEN_BASE + foc->len;
			*p++ = TCPOPT_FASTOPEN;
			*p++ = len;
		}

		memcpy(p, foc->val, foc->len);
		if ((len & 3) == 2) {
			p[foc->len] = TCPOPT_NOP;
			p[foc->len + 1] = TCPOPT_NOP;
		}
		ptr += (len + 3) >> 2;
	}

	smc_options_write(ptr, &options);

	mptcp_options_write(ptr, opts);
}

static void smc_set_option(const struct tcp_sock *tp,
			   struct tcp_out_options *opts,
			   unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

static void smc_set_option_cond(const struct tcp_sock *tp,
				const struct inet_request_sock *ireq,
				struct tcp_out_options *opts,
				unsigned int *remaining)
{
#if IS_ENABLED(CONFIG_SMC)
	if (static_branch_unlikely(&tcp_have_smc)) {
		if (tp->syn_smc && ireq->smc_ok) {
			if (*remaining >= TCPOLEN_EXP_SMC_BASE_ALIGNED) {
				opts->options |= OPTION_SMC;
				*remaining -= TCPOLEN_EXP_SMC_BASE_ALIGNED;
			}
		}
	}
#endif
}

static void mptcp_set_option_cond(const struct request_sock *req,
				  struct tcp_out_options *opts,
				  unsigned int *remaining)
{
	if (rsk_is_mptcp(req)) {
		unsigned int size;

		if (mptcp_synack_options(req, &size, &opts->mptcp)) {
			if (*remaining >= size) {
				opts->options |= OPTION_MPTCP;
				*remaining -= size;
			}
		}
	}
}

/* Compute TCP options for SYN packets. This is not the final
 * network wire format yet.
 */
static unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
				struct tcp_out_options *opts,
				struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;
	struct tcp_fastopen_request *fastopen = tp->fastopen_req;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			remaining -= TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	/* We always get an MSS option.  The option bytes which will be seen in
	 * normal data packets should timestamps be used, must be in the MSS
	 * advertised.  But we subtract them from tp->mss_cache so that
	 * calculations in tcp_sendmsg are simpler etc.  So account for this
	 * fact here if necessary.  If we don't do this correctly, as a
	 * receiver we won't recognize data packets as being full sized when we
	 * should, and thus we won't abide by the delayed ACK rules correctly.
	 * SACKs don't matter, we never delay an ACK when we have any of those
	 * going out.  */
	opts->mss = tcp_advertise_mss(sk);
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(sock_net(sk)->ipv4.sysctl_tcp_timestamps && !*md5)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tp->tsoffset;
		opts->tsecr = tp->rx_opt.ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_window_scaling)) {
		opts->ws = tp->rx_opt.rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(sock_net(sk)->ipv4.sysctl_tcp_sack)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!(OPTION_TS & opts->options)))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}

	if (fastopen && fastopen->cookie.len >= 0) {
		u32 need = fastopen->cookie.len;

		need += fastopen->cookie.exp ? TCPOLEN_EXP_FASTOPEN_BASE :
					       TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = &fastopen->cookie;
			remaining -= need;
			tp->syn_fastopen = 1;
			tp->syn_fastopen_exp = fastopen->cookie.exp ? 1 : 0;
		}
	}

	smc_set_option(tp, opts, &remaining);

	if (sk_is_mptcp(sk)) {
		unsigned int size;

		if (mptcp_syn_options(sk, skb, &size, &opts->mptcp)) {
			opts->options |= OPTION_MPTCP;
			remaining -= size;
		}
	}

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Set up TCP options for SYN-ACKs. */
static unsigned int tcp_synack_options(const struct sock *sk,
				       struct request_sock *req,
				       unsigned int mss, struct sk_buff *skb,
				       struct tcp_out_options *opts,
				       const struct tcp_md5sig_key *md5,
				       struct tcp_fastopen_cookie *foc)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	unsigned int remaining = MAX_TCP_OPTION_SPACE;

#ifdef CONFIG_TCP_MD5SIG
	if (md5) {
		opts->options |= OPTION_MD5;
		remaining -= TCPOLEN_MD5SIG_ALIGNED;

		/* We can't fit any SACK blocks in a packet with MD5 + TS
		 * options. There was discussion about disabling SACK
		 * rather than TS in order to fit in better with old,
		 * buggy kernels, but that was deemed to be unnecessary.
		 */
		ireq->tstamp_ok &= !ireq->sack_ok;
	}
#endif

	/* We always send an MSS option. */
	opts->mss = mss;
	remaining -= TCPOLEN_MSS_ALIGNED;

	if (likely(ireq->wscale_ok)) {
		opts->ws = ireq->rcv_wscale;
		opts->options |= OPTION_WSCALE;
		remaining -= TCPOLEN_WSCALE_ALIGNED;
	}
	if (likely(ireq->tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = tcp_skb_timestamp(skb) + tcp_rsk(req)->ts_off;
		opts->tsecr = req->ts_recent;
		remaining -= TCPOLEN_TSTAMP_ALIGNED;
	}
	if (likely(ireq->sack_ok)) {
		opts->options |= OPTION_SACK_ADVERTISE;
		if (unlikely(!ireq->tstamp_ok))
			remaining -= TCPOLEN_SACKPERM_ALIGNED;
	}
	if (foc != NULL && foc->len >= 0) {
		u32 need = foc->len;

		need += foc->exp ? TCPOLEN_EXP_FASTOPEN_BASE :
				   TCPOLEN_FASTOPEN_BASE;
		need = (need + 3) & ~3U;  /* Align to 32 bits */
		if (remaining >= need) {
			opts->options |= OPTION_FAST_OPEN_COOKIE;
			opts->fastopen_cookie = foc;
			remaining -= need;
		}
	}

	mptcp_set_option_cond(req, opts, &remaining);

	smc_set_option_cond(tcp_sk(sk), ireq, opts, &remaining);

	return MAX_TCP_OPTION_SPACE - remaining;
}

/* Compute TCP options for ESTABLISHED sockets. This is not the
 * final wire format yet.
 */
static unsigned int tcp_established_options(struct sock *sk, struct sk_buff *skb,
					struct tcp_out_options *opts,
					struct tcp_md5sig_key **md5)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int size = 0;
	unsigned int eff_sacks;

	opts->options = 0;

	*md5 = NULL;
#ifdef CONFIG_TCP_MD5SIG
	if (static_branch_unlikely(&tcp_md5_needed) &&
	    rcu_access_pointer(tp->md5sig_info)) {
		*md5 = tp->af_specific->md5_lookup(sk, sk);
		if (*md5) {
			opts->options |= OPTION_MD5;
			size += TCPOLEN_MD5SIG_ALIGNED;
		}
	}
#endif

	if (likely(tp->rx_opt.tstamp_ok)) {
		opts->options |= OPTION_TS;
		opts->tsval = skb ? tcp_skb_timestamp(skb) + tp->tsoffset : 0;
		opts->tsecr = tp->rx_opt.ts_recent;
		size += TCPOLEN_TSTAMP_ALIGNED;
	}

	/* MPTCP options have precedence over SACK for the limited TCP
	 * option space because a MPTCP connection would be forced to
	 * fall back to regular TCP if a required multipath option is
	 * missing. SACK still gets a chance to use whatever space is
	 * left.
	 */
	if (sk_is_mptcp(sk)) {
		unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		unsigned int opt_size = 0;

		if (mptcp_established_options(sk, skb, &opt_size, remaining,
					      &opts->mptcp)) {
			opts->options |= OPTION_MPTCP;
			size += opt_size;
		}
	}

	eff_sacks = tp->rx_opt.num_sacks + tp->rx_opt.dsack;
	if (unlikely(eff_sacks)) {
		const unsigned int remaining = MAX_TCP_OPTION_SPACE - size;
		if (unlikely(remaining < TCPOLEN_SACK_BASE_ALIGNED +
					 TCPOLEN_SACK_PERBLOCK))
			return size;

		opts->num_sack_blocks =
			min_t(unsigned int, eff_sacks,
			      (remaining - TCPOLEN_SACK_BASE_ALIGNED) /
			      TCPOLEN_SACK_PERBLOCK);

		size += TCPOLEN_SACK_BASE_ALIGNED +
			opts->num_sack_blocks * TCPOLEN_SACK_PERBLOCK;
	}

	return size;
}


/* TCP SMALL QUEUES (TSQ)
 *
 * TSQ goal is to keep small amount of skbs per tcp flow in tx queues (qdisc+dev)
 * to reduce RTT and bufferbloat.
 * We do this using a special skb destructor (tcp_wfree).
 *
 * Its important tcp_wfree() can be replaced by sock_wfree() in the event skb
 * needs to be reallocated in a driver.
 * The invariant being skb->truesize subtracted from sk->sk_wmem_alloc
 *
 * Since transmit from skb destructor is forbidden, we use a tasklet
 * to process all sockets that eventually need to send more skbs.
 * We use one tasklet per cpu, with its own queue of sockets.
 */
struct tsq_tasklet {
	struct tasklet_struct	tasklet;
	struct list_head	head; /* queue of tcp sockets */
};
static DEFINE_PER_CPU(struct tsq_tasklet, tsq_tasklet);

static void tcp_tsq_write(struct sock *sk)
{
	if ((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_FIN_WAIT1 | TCPF_CLOSING |
	     TCPF_CLOSE_WAIT  | TCPF_LAST_ACK)) {
		struct tcp_sock *tp = tcp_sk(sk);

		if (tp->lost_out > tp->retrans_out &&
		    tp->snd_cwnd > tcp_packets_in_flight(tp)) {
			tcp_mstamp_refresh(tp);
			tcp_xmit_retransmit_queue(sk);
		}

		tcp_write_xmit(sk, tcp_current_mss(sk), tp->nonagle,
			       0, GFP_ATOMIC);
	}
}

static void tcp_tsq_handler(struct sock *sk)
{
	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk))
		tcp_tsq_write(sk);
	else if (!test_and_set_bit(TCP_TSQ_DEFERRED, &sk->sk_tsq_flags))
		sock_hold(sk);
	bh_unlock_sock(sk);
}
/*
 * One tasklet per cpu tries to send more skbs.
 * We run in tasklet context but need to disable irqs when
 * transferring tsq->head because tcp_wfree() might
 * interrupt us (non NAPI drivers)
 */
static void tcp_tasklet_func(unsigned long data)
{
	struct tsq_tasklet *tsq = (struct tsq_tasklet *)data;
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct tcp_sock *tp;
	struct sock *sk;

	local_irq_save(flags);
	list_splice_init(&tsq->head, &list);
	local_irq_restore(flags);

	list_for_each_safe(q, n, &list) {
		tp = list_entry(q, struct tcp_sock, tsq_node);
		list_del(&tp->tsq_node);

		sk = (struct sock *)tp;
		smp_mb__before_atomic();
		clear_bit(TSQ_QUEUED, &sk->sk_tsq_flags);

		tcp_tsq_handler(sk);
		sk_free(sk);
	}
}

#define TCP_DEFERRED_ALL (TCPF_TSQ_DEFERRED |		\
			  TCPF_WRITE_TIMER_DEFERRED |	\
			  TCPF_DELACK_TIMER_DEFERRED |	\
			  TCPF_MTU_REDUCED_DEFERRED)
/**
 * tcp_release_cb - tcp release_sock() callback
 * @sk: socket
 *
 * called from release_sock() to perform protocol dependent
 * actions before socket release.
 */
void tcp_release_cb(struct sock *sk)
{
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	do {
		flags = sk->sk_tsq_flags;
		if (!(flags & TCP_DEFERRED_ALL))
			return;
		nflags = flags & ~TCP_DEFERRED_ALL;
	} while (cmpxchg(&sk->sk_tsq_flags, flags, nflags) != flags);

	if (flags & TCPF_TSQ_DEFERRED) {
		tcp_tsq_write(sk);
		__sock_put(sk);
	}
	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	if (flags & TCPF_WRITE_TIMER_DEFERRED) {
		tcp_write_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_DELACK_TIMER_DEFERRED) {
		tcp_delack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & TCPF_MTU_REDUCED_DEFERRED) {
		inet_csk(sk)->icsk_af_ops->mtu_reduced(sk);
		__sock_put(sk);
	}
}
EXPORT_SYMBOL(tcp_release_cb);

void __init tcp_tasklet_init(void)
{
	int i;

	for_each_possible_cpu(i) {
		struct tsq_tasklet *tsq = &per_cpu(tsq_tasklet, i);

		INIT_LIST_HEAD(&tsq->head);
		tasklet_init(&tsq->tasklet,
			     tcp_tasklet_func,
			     (unsigned long)tsq);
	}
}

/*
 * Write buffer destructor automatically called from kfree_skb.
 * We can't xmit new skbs from this context, as we might already
 * hold qdisc lock.
 */
void tcp_wfree(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long flags, nval, oval;

	/* Keep one reference on sk_wmem_alloc.
	 * Will be released by sk_free() from here or tcp_tasklet_func()
	 */
	WARN_ON(refcount_sub_and_test(skb->truesize - 1, &sk->sk_wmem_alloc));

	/* If this softirq is serviced by ksoftirqd, we are likely under stress.
	 * Wait until our queues (qdisc + devices) are drained.
	 * This gives :
	 * - less callbacks to tcp_write_xmit(), reducing stress (batches)
	 * - chance for incoming ACK (processed by another cpu maybe)
	 *   to migrate this flow (skb->ooo_okay will be eventually set)
	 */
	if (refcount_read(&sk->sk_wmem_alloc) >= SKB_TRUESIZE(1) && this_cpu_ksoftirqd() == current)
		goto out;

	for (oval = READ_ONCE(sk->sk_tsq_flags);; oval = nval) {
		struct tsq_tasklet *tsq;
		bool empty;

		if (!(oval & TSQF_THROTTLED) || (oval & TSQF_QUEUED))
			goto out;

		nval = (oval & ~TSQF_THROTTLED) | TSQF_QUEUED;
		nval = cmpxchg(&sk->sk_tsq_flags, oval, nval);
		if (nval != oval)
			continue;

		/* queue this socket to tasklet queue */
		local_irq_save(flags);
		tsq = this_cpu_ptr(&tsq_tasklet);
		empty = list_empty(&tsq->head);
		list_add(&tp->tsq_node, &tsq->head);
		if (empty)
			tasklet_schedule(&tsq->tasklet);
		local_irq_restore(flags);
		return;
	}
out:
	sk_free(sk);
}

/* Note: Called under soft irq.
 * We can call TCP stack right away, unless socket is owned by user.
 */
enum hrtimer_restart tcp_pace_kick(struct hrtimer *timer)
{
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, pacing_timer);
	struct sock *sk = (struct sock *)tp;

	tcp_tsq_handler(sk);
	sock_put(sk);

	return HRTIMER_NORESTART;
}

static void tcp_update_skb_after_send(struct sock *sk, struct sk_buff *skb,
				      u64 prior_wstamp)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sk->sk_pacing_status != SK_PACING_NONE) {
		unsigned long rate = sk->sk_pacing_rate;

		/* Original sch_fq does not pace first 10 MSS
		 * Note that tp->data_segs_out overflows after 2^32 packets,
		 * this is a minor annoyance.
		 */
		if (rate != ~0UL && rate && tp->data_segs_out >= 10) {
			u64 len_ns = div64_ul((u64)skb->len * NSEC_PER_SEC, rate);
			u64 credit = tp->tcp_wstamp_ns - prior_wstamp;

			/* take into account OS jitter */
			len_ns -= min_t(u64, len_ns / 2, credit);
			tp->tcp_wstamp_ns += len_ns;
		}
	}
	list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
}

/* This routine actually transmits TCP packets queued in by
 * tcp_do_sendmsg().  This is used by both the initial
 * transmission and possible later retransmissions.
 * All SKB's seen here are completely headerless.  It is our
 * job to build the TCP header, and pass the packet down to
 * IP so it can do the same plus pass the packet off to the
 * device.
 *
 * We are working here with either a clone of the original
 * SKB, or a fresh unique copy made by the retransmit engine.
 */
 // 负责传输 TCP 数据包。它会处理每个待发送的 TCP 数据包，构建 TCP 头部、填充选项，并最终将其传输到底层网络堆栈。
 // 这个函数不仅用于初始的 TCP 数据包发送，还包括重传机制。
 // 参数介绍：
 // *sk：执向当前 TCP 套接字。
 // *skb：指向待发送的数据包（sk_buff），它不包含 TCP 头部，需要在此函数中构建。
 // clone_it：如果为 1，表示需要克隆原始的 skb，如果为 0，则直接使用现有的 skb。
 // gfp_mask：用于分配内存时的标志。
 // rcv_nxt：接收方期望的下一个序列号（用于 ACK）
static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,
			      int clone_it, gfp_t gfp_mask, u32 rcv_nxt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet;
	struct tcp_sock *tp;
	struct tcp_skb_cb *tcb;
	struct tcp_out_options opts;
	unsigned int tcp_options_size, tcp_header_size;
	struct sk_buff *oskb = NULL;
	struct tcp_md5sig_key *md5;
	struct tcphdr *th;
	u64 prior_wstamp;
	int err;

	// 确保传入的 skb 非空，并且 skb 中确实有数据包。tcp_skb_pcount(skb) 返回 skb 中包含的数据包数量。
	BUG_ON(!skb || !tcp_skb_pcount(skb));
	tp = tcp_sk(sk);
	// 用于记录之前更新的时间戳，后面有用
	prior_wstamp = tp->tcp_wstamp_ns;
	// tp->tcp_wstamp_ns用于存储当前 TCP 套接字的 "写时间戳"（即发送数据包时的时间戳）,在每次发送数据包时更新，以便记录最后一次发送包的时间。
	// tcp_clock_cache 是用来缓存 TCP 时钟的值，防止频繁地从硬件获取时间。
	// 使用max() 函数的来更新时间戳,保证其是最新的
	tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);
	// 将时间戳存储在 skb 中，以便后续使用。
	skb->skb_mstamp_ns = tp->tcp_wstamp_ns;
	// 如果 clone_it 为 1，则对 skb 进行克隆或复制。
	if (clone_it) {
		TCP_SKB_CB(skb)->tx.in_flight = TCP_SKB_CB(skb)->end_seq
			- tp->snd_una;
		oskb = skb;
		// skb_clone() 和 pskb_copy() 都是用于复制 skb 的函数，具体选择哪个取决于是否是已克隆的 skb。
		tcp_skb_tsorted_save(oskb) {
			if (unlikely(skb_cloned(oskb)))
				skb = pskb_copy(oskb, gfp_mask);
			else
				skb = skb_clone(oskb, gfp_mask);
		} tcp_skb_tsorted_restore(oskb);

		if (unlikely(!skb))
			return -ENOBUFS;

		// 重传的 skb 可能会有非零的 skb->dev 字段，这个字段会影响克隆，所以我们清空它。
		skb->dev = NULL;
	}
	// inet_sk(sk) 获取的是套接字 sk 的 inet_sock 结构体（即 IPv4 相关的套接字信息）。这个结构体包含了与 IP 协议族相关的字段，比如源地址、目标地址等
	inet = inet_sk(sk);
	// TCP_SKB_CB(skb) 返回一个指向 struct tcp_skb_cb 结构体的指针，该结构体包含与该 sk_buff（数据包）相关的 TCP 特定信息。
	// tcb 就是用来访问该数据包的 TCP 控制块信息，例如 TCP 序列号、标志位等。
	tcb = TCP_SKB_CB(skb);
	// opts 是一个结构体，用来存储 TCP 选项的相关信息。在处理每个数据包时，要将这个结构体清零，以确保后续操作不会受到之前数据的影响
	memset(&opts, 0, sizeof(opts));

	// 检查数据包是否是 SYN 包。TCPHDR_SYN 是一个 TCP 标志，表示该数据包是一个 SYN 包，用于连接建立的过程。
	// tcb->tcp_flags & TCPHDR_SYN 会返回一个布尔值，判断是否包含 SYN 标志
	if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {
		// 如果是 SYN 包，调用 tcp_syn_options 来处理 SYN 包的选项，并计算 TCP 选项的大小。。
		// tcp_syn_options 函数将会根据当前套接字 sk 和其他信息，填充 opts 结构体，并返回这些选项的总大小。返回值将存储在 tcp_options_size 中。
		// md5 是一个指针，用于保存 MD5 签名的相关数据（如果启用了 TCP MD5 签名）
		tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
	} else {
		// 如果不是 SYN 包，则调用 tcp_established_options 处理已建立连接后的 TCP 选项（例如窗口大小、窗口扩大因子等）。
		// tcp_established_options 函数会为连接建立后的数据包计算选项并填充 opts 结构体
		tcp_options_size = tcp_established_options(sk, skb, &opts,
							   &md5);

		// 这个条件判断检查数据包是否包含多个片段。tcp_skb_pcount(skb) 返回当前 sk_buff 中的片段数。
		if (tcp_skb_pcount(skb) > 1)
			// 如果数据包包含多个片段（即 tcp_skb_pcount(skb) > 1），就强制设置 TCPHDR_PSH 标志。PSH 标志表示请求接收方尽早将数据推送到应用层，而不是等待缓冲区填满。
			// PSH 标志有助于提高接收端的聚合性能，因为接收端可以更早地将数据交给应用层，而不是等待更多的数据。
			tcb->tcp_flags |= TCPHDR_PSH;
	}
	// tcp_header_size 是数据包的总 TCP 头部大小，包括 TCP 标准头部、和所有的选项。
	// sizeof(struct tcphdr) 是标准 TCP 头部的大小（通常为 20 字节），这是 TCP 协议头部的固定部分。
	// tcp_options_size 是根据当前的 TCP 选项（如 MSS、时间戳等）计算出来的可变大小
	tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

	// skb->ooo_okay：这个字段是 sk_buff 结构中的一个标志，用来指示是否可以接受 “乱序” 的数据包。
	// 可以告诉 TCP 是否可以接受乱序的包，通常是为了启用零拷贝和加速接收缓冲区的处理。
	// sk_wmem_alloc_get(sk)：这个函数返回当前套接字的发送缓冲区的剩余空间，即写缓冲区的当前剩余空间（以字节为单位）
	// SKB_TRUESIZE(1)：这是一个宏，用于计算 sk_buff 的实际内存占用（包括所有的附加数据和头部）。SKB_TRUESIZE(1) 返回一个表示单个数据包大小的内存值。
	skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1);

	// skb->pfmemalloc：这是 sk_buff 结构中的一个标志，表示此数据包是否是通过 SOCK_MEMALLOC 分配的。
	// 将这个标志清零，表示当前数据包不使用 SOCK_MEMALLOC 分配的内存空间
	skb->pfmemalloc = 0;

	// 该函数将 skb 的数据区域向前推移 tcp_header_size 字节。这个操作相当于为 TCP 数据包腾出空间，准备存放 TCP 头部信息。
	skb_push(skb, tcp_header_size);
	// 此函数重置 skb 的传输层头部指针。即将 skb->transport_header 设置为当前数据位置，通常在设置 TCP/IP 头部时调用，以确保后续的 TCP/IP 头部正确设置。
	skb_reset_transport_header(skb);

	// 此函数将 skb 标记为 "孤立"（orphan）。
	// 具体来说，skb_orphan 会将 skb->sk 设置为 NULL，并防止内存回收等操作。
	// 通常是在从 TCP 发送队列或回收队列中删除数据包时调用，以避免内存资源被过早释放。
	skb_orphan(skb);
	// sk_buff 结构中的一个字段，指向与当前数据包关联的套接字
	skb->sk = sk;
	//s kb->destructor：这是 sk_buff 结构中的一个函数指针，用来在数据包不再使用时调用清理操作。它指定了一个清理函数，负责释放该数据包占用的资源。
	// skb_is_tcp_pure_ack(skb)：这是一个检查当前数据包是否是一个纯 ACK 数据包的函数。如果是纯 ACK 包，则不需要发送数据，只需要确认连接的状态。
	// __sock_wfree：如果是纯 ACK 包，则指定 __sock_wfree 作为清理函数。
	// tcp_wfree：如果不是纯 ACK 包，则指定 tcp_wfree 作为清理函数。tcp_wfree 用于清理非 ACK 数据包占用的资源。
	skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;
	// 此函数设置 skb 的哈希值（skb->hash）以便后续路由、负载均衡等操作使用。哈希值通常基于源/目的地址、端口等信息计算，用于确定数据包的传输路径。
	skb_set_hash_from_sk(skb, sk);
	// 此处用来增加套接字发送缓冲区的内存分配大小。
	// skb->truesize 是当前数据包占用的内存大小（包括头部、数据等），
	// 而 sk->sk_wmem_alloc 是套接字的内存分配统计字段，表示套接字当前已分配的内存，通过增加该值，记录当前 skb 数据包对发送缓冲区的内存占用。
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);

	// 这行代码将当前套接字的目标确认标志（sk_dst_pending_confirm）设置到 skb 中。目标确认标志表示在数据包传输时是否需要确认目标地址。
	// 用于处理路由和目标地址缓存的确认机制，确保目标地址的正确性
	skb_set_dst_pending_confirm(skb, sk->sk_dst_pending_confirm);

	// 构建TCP头部
	// th：指向 TCP 头部。
	// th->seq 和 th->ack_seq：设置 TCP 的序列号和确认号。
	// th->check：此处将校验和字段清零，稍后会根据数据计算校验和。
	// th->urg_ptr：紧急指针，只有在使用紧急数据时才会非零。
	th = (struct tcphdr *)skb->data;
	th->source		= inet->inet_sport;
	th->dest		= inet->inet_dport;
	th->seq			= htonl(tcb->seq);
	th->ack_seq		= htonl(rcv_nxt);
	*(((__be16 *)th) + 6)	= htons(((tcp_header_size >> 2) << 12) |
					tcb->tcp_flags);

	th->check		= 0;
	th->urg_ptr		= 0;

	// tcp_urg_mode(tp)：这是一个检查TCP连接是否处于紧急模式（Urgent Mode）的方法。紧急模式指示TCP协议栈需要处理紧急数据（URG位设置为1），这些数据会优先处理。
	// before(tcb->seq, tp->snd_up)：before 是一个宏，用于判断给定的序列号 tcb->seq 是否小于 snd_up。snd_up 是 TCP 中一个特殊的 "urgent pointer" 序列号，表示发送的紧急数据的结束位置。
	// unlikely：这表示这个条件块不太可能发生，编译器会根据这个假设优化代码生成。
	if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {
		// before(tp->snd_up, tcb->seq + 0x10000)：如果 snd_up 小于 tcb->seq + 0x10000，
		// 意味着紧急数据没有超过一个 TCP 滑动窗口的大小。即当前的序列号不会太远超过 snd_up，紧急指针可以有效地设置。
		if (before(tp->snd_up, tcb->seq + 0x10000)) {
			// 将紧急指针 (urg_ptr) 设置为 snd_up - seq，并将其转换为网络字节序 (htons)。
			th->urg_ptr = htons(tp->snd_up - tcb->seq);
			// 设置 TCP 头部中的 URG 标志为 1，表示这个数据包包含紧急数据。
			th->urg = 1;
		// after 判断条件表示数据包的序列号加上一个较大的值（0xFFFF）是否大于 snd_nxt，
		// 即检查当前数据包是否已超出窗口范围。如果超出了窗口范围，则设置紧急指针为最大值。
		} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {
			// 此时设置紧急指针为最大值 0xFFFF，表示数据包包含的紧急数据超出了当前滑动窗口的最大范围。
			th->urg_ptr = htons(0xFFFF);
			// // 设置 TCP 头部中的 URG 标志为 1，表示这个数据包包含紧急数据。
			th->urg = 1;
		}
	}

	// 将 TCP 选项写入到 TCP 头部。th + 1 是指向 TCP 头部之后的位置，它将指向 TCP 选项区域。
	// tcp_options_write 会将选项写入到这个位置。opts 是一个结构体，包含了TCP选项的详细信息，
	tcp_options_write((__be32 *)(th + 1), tp, &opts);
	// skb_shinfo(skb)：这是访问 skb 的共享信息区域的宏。共享信息区域存储了与 skb 相关的附加信息，如 GSO（大段分段）信息。
	// gso_type：这是一个 GSO 类型字段，标志着当前 skb 是否使用了大段分段。它指定了网络栈如何处理分段。
	// sk->sk_gso_type：获取套接字的 GSO 类型，并将其分配给 skb，确保 skb 的 GSO 处理与套接字一致。
	skb_shinfo(skb)->gso_type = sk->sk_gso_type;
	// likely：此宏告诉编译器该条件更有可能为 true，可以优化代码生成。
	// !(tcb->tcp_flags & TCPHDR_SYN)：此条件检查 TCP 数据包是否为 SYN 包。
	// 如果 tcb->tcp_flags & TCPHDR_SYN 为真，则表示这是一个 SYN 包，反之则表示这不是 SYN 包。
	if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
		// tcp_select_window(sk)：此函数计算并返回当前连接的窗口大小（即 TCP 发送缓冲区的剩余空间）。
		// htons：将返回的窗口大小转换为网络字节序。
	    // th->window：设置 TCP 头部中的窗口大小字段。
		// 如果这不是一个SYN包则设置TCP头部窗口大小为当前连接的窗口大小
		th->window      = htons(tcp_select_window(sk));
		// tcp_ecn_send(sk, skb, th, tcp_header_size);：这是一个处理 TCP ECN（显式拥塞通知）功能的函数。
		// 如果启用了 ECN，函数会设置相应的 ECN 标志，并更新 TCP 头部中的相应字段。
		tcp_ecn_send(sk, skb, th, tcp_header_size);
	} else {
		// 对于 SYN 包或 SYN/ACK 包，窗口大小不会根据发送方的可用空间进行缩放，
		// 而是固定为接收方的窗口（rcv_wnd），并且最大为 65535（16 位字段的最大值）。
		th->window	= htons(min(tp->rcv_wnd, 65535U));
	}
// 这部分代码是与 MD5 校验相关的，通过定义CONFIG_TCP_MD5SIG可以选择是否进行MD5校验，只有定义了CONFIG_TCP_MD5SIG才会执行以下检查。
// TCP连接可以使用 MD5 签名来验证数据包的完整性。MD5 校验用于确保数据在传输过程中没有被篡改。
#ifdef CONFIG_TCP_MD5SIG
	// 如果 MD5 校验已启用且连接配置了 MD5 校验，则进行 MD5 计算。
	if (md5) {
		// 这是一个函数调用，作用是修改套接字 sk 的某些特性。NETIF_F_GSO_MASK 是一个与 GSO（大段分段）相关的标志。此行代码的目的是确保套接字不会因为 GSO 类型而受到影响。
		sk_nocaps_add(sk, NETIF_F_GSO_MASK);
		// pts.hash_location 是 MD5 校验和计算需要的地址，通常会指定某个特定位置来存储哈希值。md5 是用于签名的密钥，sk 是当前的套接字，skb 是当前的发送缓冲区（即数据包）。
		// 这一行代码实际上调用了用于计算 MD5 校验和的函数。tp->af_specific 是指向与地址族相关的特定操作函数指针结构，
		// calc_md5_hash 是一个虚拟函数，它根据 TCP 连接的配置（如 MD5 密钥）计算数据包的 MD5 哈希。
		tp->af_specific->calc_md5_hash(opts.hash_location,
					       md5, sk, skb);
	}
#endif

	// 确保发送的数据包满足特定地址族的要求
	icsk->icsk_af_ops->send_check(sk, skb);

	// 如果当前的 TCP 数据包是一个确认（ACK）包
	if (likely(tcb->tcp_flags & TCPHDR_ACK))
		// 这行代码处理 ACK 数据包发送后的事件。tcp_event_ack_sent 会记录发送 ACK 包后的一些统计信息。
		// tcp_skb_pcount(skb) 返回该 skb（数据包）中的段数，这对于多段 TCP 包是有用的。
		// rcv_nxt 是接收方期望接收的下一个序列号
		tcp_event_ack_sent(sk, tcp_skb_pcount(skb), rcv_nxt);
	// 判断当前的 skb 数据包的长度是否大于 TCP 头部的长度。如果是，说明这个数据包包含了有效的 TCP 数据。
	if (skb->len != tcp_header_size) {
		// 如果包含有效数据
		// 使用tcp_event_data_sent 处理发送数据包后的事件，记录数据包发送的统计信息
		tcp_event_data_sent(tp, sk);
		// 更新 TCP 连接发送的段数统计。
		// tcp_skb_pcount(skb) 返回当前数据包中包含的 TCP 段数（通常是 1，除非启用了 GSO）。
		tp->data_segs_out += tcp_skb_pcount(skb);
		// 更新已发送的字节数。
		// skb->len 是数据包的总长度，而 tcp_header_size 是 TCP 头部的大小，因此 skb->len - tcp_header_size 是数据包中有效数据的大小
		tp->bytes_sent += skb->len - tcp_header_size;
	}

	// after 是一个宏，用来判断一个序列号是否大于另一个。
	// 这里的意思是，如果当前数据包的结束序列号 tcb->end_seq 大于发送窗口中的下一个序列号 tp->snd_nxt，或者当前数据包的序列号与结束序列号相等，则进行以下统计更新：
	if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)
		// 这行代码将发送的数据包段数添加到 TCP 统计信息中。TCP_MIB_OUTSEGS 统计的是发送的 TCP 段的数量。
		TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,
			      tcp_skb_pcount(skb));

	// 这行代码更新 TCP 连接的发送段数统计。tp->segs_out 是发送的段总数，tcp_skb_pcount(skb) 返回当前数据包中段的数量。
	tp->segs_out += tcp_skb_pcount(skb);

	// skb_shinfo(skb)->gso_segs 用来设置数据包的段数，tcp_skb_pcount(skb) 返回该数据包中的段数。
	// GSO（大段分段，Generic Segmentation Offload）：一个优化技术，允许网络设备分割大数据包而不需要操作系统干预
	skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);
	// 这行代码设置 GSO 大小。tcp_skb_mss(skb) 返回数据包的最大报文段大小（MSS），这是分段时使用的最大单个段的大小。
	skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

	// skb->cb 是用于存储与 skb 相关的临时数据。memset 将它清零，以清除可能残留的过时信息。
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),
			       sizeof(struct inet6_skb_parm)));

	// 根据 TCP 连接的延迟参数 tcp_tx_delay 对数据包的时间戳 skb_mstamp_ns 进行调整
	tcp_add_tx_delay(skb, tp);

	// queue_xmit 是将数据包提交给网络设备驱动进行发送的操作。它调用与当前地址族（IPv4 或 IPv6）相关的发送函数（更底层的数据发送函数，实际上网络协议栈就是一层调一层，层层加包）。
	// inet->cork.fl 是用于传输的数据包“夹层”字段，用于合并多条数据（例如，TCP 快速打开、合并传输）。
	err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);

	// 检查 queue_xmit 函数是否返回了一个错误代码。
	if (unlikely(err > 0)) {
		// 如果发生了错误，并且该错误可能与网络拥塞控制（CWR，Congestion Window Reduced）有关，进入 CWR 状态。这是为了处理 TCP 拥塞窗口减小的情况。
		tcp_enter_cwr(sk);
		err = net_xmit_eval(err);
	}
	// 如果没有发生错误，并且 oskb 存在
	if (!err && oskb) {
		// 这行代码在发送数据包之后更新 oskb 的状态，prior_wstamp 是先前的时间戳。
		tcp_update_skb_after_send(sk, oskb, prior_wstamp);
		// 更新 TCP 发送速率或相关的统计信息，以便根据发送的数据包计算发送速率。
		tcp_rate_skb_sent(sk, oskb);
	}
	return err;
}

static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,
			    gfp_t gfp_mask)
{
	return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,
				  tcp_sk(sk)->rcv_nxt);
}

/* This routine just queues the buffer for sending.
 *
 * NOTE: probe0 timer is not checked, do not forget tcp_push_pending_frames,
 * otherwise socket can stall.
 */
static void tcp_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Advance write_seq and place onto the write_queue. */
	WRITE_ONCE(tp->write_seq, TCP_SKB_CB(skb)->end_seq);
	__skb_header_release(skb);
	tcp_add_write_queue_tail(sk, skb);
	sk_wmem_queued_add(sk, skb->truesize);
	sk_mem_charge(sk, skb->truesize);
}

/* Initialize TSO segments for a packet. */
static void tcp_set_skb_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	if (skb->len <= mss_now) {
		/* Avoid the costly divide in the normal
		 * non-TSO case.
		 */
		tcp_skb_pcount_set(skb, 1);
		TCP_SKB_CB(skb)->tcp_gso_size = 0;
	} else {
		tcp_skb_pcount_set(skb, DIV_ROUND_UP(skb->len, mss_now));
		TCP_SKB_CB(skb)->tcp_gso_size = mss_now;
	}
}

/* Pcount in the middle of the write queue got changed, we need to do various
 * tweaks to fix counters
 */
static void tcp_adjust_pcount(struct sock *sk, const struct sk_buff *skb, int decr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	tp->packets_out -= decr;

	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		tp->sacked_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS)
		tp->retrans_out -= decr;
	if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
		tp->lost_out -= decr;

	/* Reno case is special. Sigh... */
	if (tcp_is_reno(tp) && decr > 0)
		tp->sacked_out -= min_t(u32, tp->sacked_out, decr);

	if (tp->lost_skb_hint &&
	    before(TCP_SKB_CB(skb)->seq, TCP_SKB_CB(tp->lost_skb_hint)->seq) &&
	    (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED))
		tp->lost_cnt_hint -= decr;

	tcp_verify_left_out(tp);
}

static bool tcp_has_tx_tstamp(const struct sk_buff *skb)
{
	return TCP_SKB_CB(skb)->txstamp_ack ||
		(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP);
}

static void tcp_fragment_tstamp(struct sk_buff *skb, struct sk_buff *skb2)
{
	struct skb_shared_info *shinfo = skb_shinfo(skb);

	if (unlikely(tcp_has_tx_tstamp(skb)) &&
	    !before(shinfo->tskey, TCP_SKB_CB(skb2)->seq)) {
		struct skb_shared_info *shinfo2 = skb_shinfo(skb2);
		u8 tsflags = shinfo->tx_flags & SKBTX_ANY_TSTAMP;

		shinfo->tx_flags &= ~tsflags;
		shinfo2->tx_flags |= tsflags;
		swap(shinfo->tskey, shinfo2->tskey);
		TCP_SKB_CB(skb2)->txstamp_ack = TCP_SKB_CB(skb)->txstamp_ack;
		TCP_SKB_CB(skb)->txstamp_ack = 0;
	}
}

static void tcp_skb_fragment_eor(struct sk_buff *skb, struct sk_buff *skb2)
{
	TCP_SKB_CB(skb2)->eor = TCP_SKB_CB(skb)->eor;
	TCP_SKB_CB(skb)->eor = 0;
}

/* Insert buff after skb on the write or rtx queue of sk.  */
static void tcp_insert_write_queue_after(struct sk_buff *skb,
					 struct sk_buff *buff,
					 struct sock *sk,
					 enum tcp_queue tcp_queue)
{
	if (tcp_queue == TCP_FRAG_IN_WRITE_QUEUE)
		__skb_queue_after(&sk->sk_write_queue, skb, buff);
	else
		tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);
}

/* Function to create two new TCP segments.  Shrinks the given segment
 * to the specified size and appends a new segment with the rest of the
 * packet to the list.  This won't be called frequently, I hope.
 * Remember, these are still headerless SKBs at this point.
 */
int tcp_fragment(struct sock *sk, enum tcp_queue tcp_queue,
		 struct sk_buff *skb, u32 len,
		 unsigned int mss_now, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int nsize, old_factor;
	long limit;
	int nlen;
	u8 flags;

	if (WARN_ON(len > skb->len))
		return -EINVAL;

	nsize = skb_headlen(skb) - len;
	if (nsize < 0)
		nsize = 0;

	/* tcp_sendmsg() can overshoot sk_wmem_queued by one full size skb.
	 * We need some allowance to not penalize applications setting small
	 * SO_SNDBUF values.
	 * Also allow first and last skb in retransmit queue to be split.
	 */
	limit = sk->sk_sndbuf + 2 * SKB_TRUESIZE(GSO_MAX_SIZE);
	if (unlikely((sk->sk_wmem_queued >> 1) > limit &&
		     tcp_queue != TCP_FRAG_IN_WRITE_QUEUE &&
		     skb != tcp_rtx_queue_head(sk) &&
		     skb != tcp_rtx_queue_tail(sk))) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPWQUEUETOOBIG);
		return -ENOMEM;
	}

	if (skb_unclone(skb, gfp))
		return -ENOMEM;

	/* Get a new skb... force flag on. */
	buff = sk_stream_alloc_skb(sk, nsize, gfp, true);
	if (!buff)
		return -ENOMEM; /* We'll just try again later. */
	skb_copy_decrypted(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	sk_mem_charge(sk, buff->truesize);
	nlen = skb->len - len - nsize;
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;
	TCP_SKB_CB(buff)->sacked = TCP_SKB_CB(skb)->sacked;
	tcp_skb_fragment_eor(skb, buff);

	skb_split(skb, buff, len);

	buff->ip_summed = CHECKSUM_PARTIAL;

	buff->tstamp = skb->tstamp;
	tcp_fragment_tstamp(skb, buff);

	old_factor = tcp_skb_pcount(skb);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* Update delivered info for the new segment */
	TCP_SKB_CB(buff)->tx = TCP_SKB_CB(skb)->tx;

	/* If this packet has been sent out already, we must
	 * adjust the various packet counters.
	 */
	if (!before(tp->snd_nxt, TCP_SKB_CB(buff)->end_seq)) {
		int diff = old_factor - tcp_skb_pcount(skb) -
			tcp_skb_pcount(buff);

		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
	}

	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, tcp_queue);
	if (tcp_queue == TCP_FRAG_IN_RTX_QUEUE)
		list_add(&buff->tcp_tsorted_anchor, &skb->tcp_tsorted_anchor);

	return 0;
}

/* This is similar to __pskb_pull_tail(). The difference is that pulled
 * data is not copied, but immediately discarded.
 */
static int __pskb_trim_head(struct sk_buff *skb, int len)
{
	struct skb_shared_info *shinfo;
	int i, k, eat;

	eat = min_t(int, len, skb_headlen(skb));
	if (eat) {
		__skb_pull(skb, eat);
		len -= eat;
		if (!len)
			return 0;
	}
	eat = len;
	k = 0;
	shinfo = skb_shinfo(skb);
	for (i = 0; i < shinfo->nr_frags; i++) {
		int size = skb_frag_size(&shinfo->frags[i]);

		if (size <= eat) {
			skb_frag_unref(skb, i);
			eat -= size;
		} else {
			shinfo->frags[k] = shinfo->frags[i];
			if (eat) {
				skb_frag_off_add(&shinfo->frags[k], eat);
				skb_frag_size_sub(&shinfo->frags[k], eat);
				eat = 0;
			}
			k++;
		}
	}
	shinfo->nr_frags = k;

	skb->data_len -= len;
	skb->len = skb->data_len;
	return len;
}

/* Remove acked data from a packet in the transmit queue. */
int tcp_trim_head(struct sock *sk, struct sk_buff *skb, u32 len)
{
	u32 delta_truesize;

	if (skb_unclone(skb, GFP_ATOMIC))
		return -ENOMEM;

	delta_truesize = __pskb_trim_head(skb, len);

	TCP_SKB_CB(skb)->seq += len;
	skb->ip_summed = CHECKSUM_PARTIAL;

	if (delta_truesize) {
		skb->truesize	   -= delta_truesize;
		sk_wmem_queued_add(sk, -delta_truesize);
		sk_mem_uncharge(sk, delta_truesize);
		sock_set_flag(sk, SOCK_QUEUE_SHRUNK);
	}

	/* Any change of skb->len requires recalculation of tso factor. */
	if (tcp_skb_pcount(skb) > 1)
		tcp_set_skb_tso_segs(skb, tcp_skb_mss(skb));

	return 0;
}

/* Calculate MSS not accounting any TCP options.  */
static inline int __tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	/* Calculate base mss without TCP options:
	   It is MMS_S - sizeof(tcphdr) of rfc1122
	 */
	mss_now = pmtu - icsk->icsk_af_ops->net_header_len - sizeof(struct tcphdr);

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mss_now -= icsk->icsk_af_ops->net_frag_header_len;
	}

	/* Clamp it (mss_clamp does not include tcp options) */
	if (mss_now > tp->rx_opt.mss_clamp)
		mss_now = tp->rx_opt.mss_clamp;

	/* Now subtract optional transport overhead */
	mss_now -= icsk->icsk_ext_hdr_len;

	/* Then reserve room for full set of TCP options and 8 bytes of data */
	mss_now = max(mss_now, sock_net(sk)->ipv4.sysctl_tcp_min_snd_mss);
	return mss_now;
}

/* Calculate MSS. Not accounting for SACKs here.  */
int tcp_mtu_to_mss(struct sock *sk, int pmtu)
{
	/* Subtract TCP options size, not including SACKs */
	return __tcp_mtu_to_mss(sk, pmtu) -
	       (tcp_sk(sk)->tcp_header_len - sizeof(struct tcphdr));
}

/* Inverse of above */
int tcp_mss_to_mtu(struct sock *sk, int mss)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	int mtu;

	mtu = mss +
	      tp->tcp_header_len +
	      icsk->icsk_ext_hdr_len +
	      icsk->icsk_af_ops->net_header_len;

	/* IPv6 adds a frag_hdr in case RTAX_FEATURE_ALLFRAG is set */
	if (icsk->icsk_af_ops->net_frag_header_len) {
		const struct dst_entry *dst = __sk_dst_get(sk);

		if (dst && dst_allfrag(dst))
			mtu += icsk->icsk_af_ops->net_frag_header_len;
	}
	return mtu;
}
EXPORT_SYMBOL(tcp_mss_to_mtu);

/* MTU probing init per socket */
void tcp_mtup_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct net *net = sock_net(sk);

	icsk->icsk_mtup.enabled = net->ipv4.sysctl_tcp_mtu_probing > 1;
	icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp + sizeof(struct tcphdr) +
			       icsk->icsk_af_ops->net_header_len;
	icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, net->ipv4.sysctl_tcp_base_mss);
	icsk->icsk_mtup.probe_size = 0;
	if (icsk->icsk_mtup.enabled)
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
}
EXPORT_SYMBOL(tcp_mtup_init);

/* This function synchronize snd mss to current pmtu/exthdr set.

   tp->rx_opt.user_mss is mss set by user by TCP_MAXSEG. It does NOT counts
   for TCP options, but includes only bare TCP header.

   tp->rx_opt.mss_clamp is mss negotiated at connection setup.
   It is minimum of user_mss and mss received with SYN.
   It also does not include TCP options.

   inet_csk(sk)->icsk_pmtu_cookie is last pmtu, seen by this function.

   tp->mss_cache is current effective sending mss, including
   all tcp options except for SACKs. It is evaluated,
   taking into account current pmtu, but never exceeds
   tp->rx_opt.mss_clamp.

   NOTE1. rfc1122 clearly states that advertised MSS
   DOES NOT include either tcp or ip options.

   NOTE2. inet_csk(sk)->icsk_pmtu_cookie and tp->mss_cache
   are READ ONLY outside this function.		--ANK (980731)
 */
unsigned int tcp_sync_mss(struct sock *sk, u32 pmtu)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct inet_connection_sock *icsk = inet_csk(sk);
	int mss_now;

	if (icsk->icsk_mtup.search_high > pmtu)
		icsk->icsk_mtup.search_high = pmtu;

	mss_now = tcp_mtu_to_mss(sk, pmtu);
	mss_now = tcp_bound_to_half_wnd(tp, mss_now);

	/* And store cached results */
	icsk->icsk_pmtu_cookie = pmtu;
	if (icsk->icsk_mtup.enabled)
		mss_now = min(mss_now, tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_low));
	tp->mss_cache = mss_now;

	return mss_now;
}
EXPORT_SYMBOL(tcp_sync_mss);

/* Compute the current effective MSS, taking SACKs and IP options,
 * and even PMTU discovery events into account.
 */
unsigned int tcp_current_mss(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 mss_now;
	unsigned int header_len;
	struct tcp_out_options opts;
	struct tcp_md5sig_key *md5;

	mss_now = tp->mss_cache;

	if (dst) {
		u32 mtu = dst_mtu(dst);
		if (mtu != inet_csk(sk)->icsk_pmtu_cookie)
			mss_now = tcp_sync_mss(sk, mtu);
	}

	header_len = tcp_established_options(sk, NULL, &opts, &md5) +
		     sizeof(struct tcphdr);
	/* The mss_cache is sized based on tp->tcp_header_len, which assumes
	 * some common options. If this is an odd packet (because we have SACK
	 * blocks etc) then our calculated header_len will be different, and
	 * we have to adjust mss_now correspondingly */
	if (header_len != tp->tcp_header_len) {
		int delta = (int) header_len - tp->tcp_header_len;
		mss_now -= delta;
	}

	return mss_now;
}

/* RFC2861, slow part. Adjust cwnd, after it was not full during one rto.
 * As additional protections, we do not touch cwnd in retransmission phases,
 * and if application hit its sndbuf limit recently.
 */
static void tcp_cwnd_application_limited(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Open &&
	    sk->sk_socket && !test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		/* Limited by application or receiver window. */
		u32 init_win = tcp_init_cwnd(tp, __sk_dst_get(sk));
		u32 win_used = max(tp->snd_cwnd_used, init_win);
		if (win_used < tp->snd_cwnd) {
			tp->snd_ssthresh = tcp_current_ssthresh(sk);
			tp->snd_cwnd = (tp->snd_cwnd + win_used) >> 1;
		}
		tp->snd_cwnd_used = 0;
	}
	tp->snd_cwnd_stamp = tcp_jiffies32;
}

static void tcp_cwnd_validate(struct sock *sk, bool is_cwnd_limited)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	struct tcp_sock *tp = tcp_sk(sk);

	/* Track the maximum number of outstanding packets in each
	 * window, and remember whether we were cwnd-limited then.
	 */
	if (!before(tp->snd_una, tp->max_packets_seq) ||
	    tp->packets_out > tp->max_packets_out) {
		tp->max_packets_out = tp->packets_out;
		tp->max_packets_seq = tp->snd_nxt;
		tp->is_cwnd_limited = is_cwnd_limited;
	}

	if (tcp_is_cwnd_limited(sk)) {
		/* Network is feed fully. */
		tp->snd_cwnd_used = 0;
		tp->snd_cwnd_stamp = tcp_jiffies32;
	} else {
		/* Network starves. */
		if (tp->packets_out > tp->snd_cwnd_used)
			tp->snd_cwnd_used = tp->packets_out;

		if (sock_net(sk)->ipv4.sysctl_tcp_slow_start_after_idle &&
		    (s32)(tcp_jiffies32 - tp->snd_cwnd_stamp) >= inet_csk(sk)->icsk_rto &&
		    !ca_ops->cong_control)
			tcp_cwnd_application_limited(sk);

		/* The following conditions together indicate the starvation
		 * is caused by insufficient sender buffer:
		 * 1) just sent some data (see tcp_write_xmit)
		 * 2) not cwnd limited (this else condition)
		 * 3) no more data to send (tcp_write_queue_empty())
		 * 4) application is hitting buffer limit (SOCK_NOSPACE)
		 */
		if (tcp_write_queue_empty(sk) && sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &sk->sk_socket->flags) &&
		    (1 << sk->sk_state) & (TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
			tcp_chrono_start(sk, TCP_CHRONO_SNDBUF_LIMITED);
	}
}

/* Minshall's variant of the Nagle send check. */
static bool tcp_minshall_check(const struct tcp_sock *tp)
{
	return after(tp->snd_sml, tp->snd_una) &&
		!after(tp->snd_sml, tp->snd_nxt);
}

/* Update snd_sml if this skb is under mss
 * Note that a TSO packet might end with a sub-mss segment
 * The test is really :
 * if ((skb->len % mss) != 0)
 *        tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
 * But we can avoid doing the divide again given we already have
 *  skb_pcount = skb->len / mss_now
 */
static void tcp_minshall_update(struct tcp_sock *tp, unsigned int mss_now,
				const struct sk_buff *skb)
{
	if (skb->len < tcp_skb_pcount(skb) * mss_now)
		tp->snd_sml = TCP_SKB_CB(skb)->end_seq;
}

/* Return false, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized. (provided by caller in %partial bool)
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_CORK is not set, and TCP_NODELAY is set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static bool tcp_nagle_check(bool partial, const struct tcp_sock *tp,
			    int nonagle)
{
	return partial &&
		((nonagle & TCP_NAGLE_CORK) ||
		 (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}

/* Return how many segs we'd like on a TSO packet,
 * to send one TSO packet per ms
 */
static u32 tcp_tso_autosize(const struct sock *sk, unsigned int mss_now,
			    int min_tso_segs)
{
	u32 bytes, segs;

	bytes = min_t(unsigned long,
		      sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift),
		      sk->sk_gso_max_size - 1 - MAX_TCP_HEADER);

	/* Goal is to send at least one packet per ms,
	 * not one big TSO packet every 100 ms.
	 * This preserves ACK clocking and is consistent
	 * with tcp_tso_should_defer() heuristic.
	 */
	segs = max_t(u32, bytes / mss_now, min_tso_segs);

	return segs;
}

/* Return the number of segments we want in the skb we are transmitting.
 * See if congestion control module wants to decide; otherwise, autosize.
 */
static u32 tcp_tso_segs(struct sock *sk, unsigned int mss_now)
{
	const struct tcp_congestion_ops *ca_ops = inet_csk(sk)->icsk_ca_ops;
	u32 min_tso, tso_segs;

	min_tso = ca_ops->min_tso_segs ?
			ca_ops->min_tso_segs(sk) :
			sock_net(sk)->ipv4.sysctl_tcp_min_tso_segs;

	tso_segs = tcp_tso_autosize(sk, mss_now, min_tso);
	return min_t(u32, tso_segs, sk->sk_gso_max_segs);
}

/* Returns the portion of skb which can be sent right away */
static unsigned int tcp_mss_split_point(const struct sock *sk,
					const struct sk_buff *skb,
					unsigned int mss_now,
					unsigned int max_segs,
					int nonagle)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 partial, needed, window, max_len;

	window = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;
	max_len = mss_now * max_segs;

	if (likely(max_len <= window && skb != tcp_write_queue_tail(sk)))
		return max_len;

	needed = min(skb->len, window);

	if (max_len <= needed)
		return max_len;

	partial = needed % mss_now;
	/* If last segment is not a full MSS, check if Nagle rules allow us
	 * to include this last segment in this skb.
	 * Otherwise, we'll split the skb at last MSS boundary
	 */
	if (tcp_nagle_check(partial != 0, tp, nonagle))
		return needed - partial;

	return needed;
}

/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int tcp_cwnd_test(const struct tcp_sock *tp,
					 const struct sk_buff *skb)
{
	u32 in_flight, cwnd, halfcwnd;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tcp_skb_pcount(skb) == 1)
		return 1;

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight >= cwnd)
		return 0;

	/* For better scheduling, ensure we have at least
	 * 2 GSO packets in flight.
	 */
	halfcwnd = max(cwnd >> 1, 1U);
	return min(halfcwnd, cwnd - in_flight);
}

/* Initialize TSO state of a skb.
 * This must be invoked the first time we consider transmitting
 * SKB onto the wire.
 */
static int tcp_init_tso_segs(struct sk_buff *skb, unsigned int mss_now)
{
	int tso_segs = tcp_skb_pcount(skb);

	if (!tso_segs || (tso_segs > 1 && tcp_skb_mss(skb) != mss_now)) {
		tcp_set_skb_tso_segs(skb, mss_now);
		tso_segs = tcp_skb_pcount(skb);
	}
	return tso_segs;
}


/* Return true if the Nagle test allows this packet to be
 * sent now.
 */
static inline bool tcp_nagle_test(const struct tcp_sock *tp, const struct sk_buff *skb,
				  unsigned int cur_mss, int nonagle)
{
	/* Nagle rule does not apply to frames, which sit in the middle of the
	 * write_queue (they have no chances to get new data).
	 *
	 * This is implemented in the callers, where they modify the 'nonagle'
	 * argument based upon the location of SKB in the send queue.
	 */
	if (nonagle & TCP_NAGLE_PUSH)
		return true;

	/* Don't use the nagle rule for urgent data (or for the final FIN). */
	if (tcp_urg_mode(tp) || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	if (!tcp_nagle_check(skb->len < cur_mss, tp, nonagle))
		return true;

	return false;
}

/* Does at least the first segment of SKB fit into the send window? */
static bool tcp_snd_wnd_test(const struct tcp_sock *tp,
			     const struct sk_buff *skb,
			     unsigned int cur_mss)
{
	u32 end_seq = TCP_SKB_CB(skb)->end_seq;

	if (skb->len > cur_mss)
		end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

	return !after(end_seq, tcp_wnd_end(tp));
}

/* Trim TSO SKB to LEN bytes, put the remaining data into a new packet
 * which is put after SKB on the list.  It is very much like
 * tcp_fragment() except that it may make several kinds of assumptions
 * in order to speed up the splitting operation.  In particular, we
 * know that all the data is in scatter-gather pages, and that the
 * packet has never been sent out before (and thus is not cloned).
 */
static int tso_fragment(struct sock *sk, struct sk_buff *skb, unsigned int len,
			unsigned int mss_now, gfp_t gfp)
{
	int nlen = skb->len - len;
	struct sk_buff *buff;
	u8 flags;

	/* All of a TSO frame must be composed of paged data.  */
	if (skb->len != skb->data_len)
		return tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
				    skb, len, mss_now, gfp);

	buff = sk_stream_alloc_skb(sk, 0, gfp, true);
	if (unlikely(!buff))
		return -ENOMEM;
	skb_copy_decrypted(buff, skb);

	sk_wmem_queued_add(sk, buff->truesize);
	sk_mem_charge(sk, buff->truesize);
	buff->truesize += nlen;
	skb->truesize -= nlen;

	/* Correct the sequence numbers. */
	TCP_SKB_CB(buff)->seq = TCP_SKB_CB(skb)->seq + len;
	TCP_SKB_CB(buff)->end_seq = TCP_SKB_CB(skb)->end_seq;
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(buff)->seq;

	/* PSH and FIN should only be set in the second packet. */
	flags = TCP_SKB_CB(skb)->tcp_flags;
	TCP_SKB_CB(skb)->tcp_flags = flags & ~(TCPHDR_FIN | TCPHDR_PSH);
	TCP_SKB_CB(buff)->tcp_flags = flags;

	/* This packet was never sent out yet, so no SACK bits. */
	TCP_SKB_CB(buff)->sacked = 0;

	tcp_skb_fragment_eor(skb, buff);

	buff->ip_summed = CHECKSUM_PARTIAL;
	skb_split(skb, buff, len);
	tcp_fragment_tstamp(skb, buff);

	/* Fix up tso_factor for both original and new SKB.  */
	tcp_set_skb_tso_segs(skb, mss_now);
	tcp_set_skb_tso_segs(buff, mss_now);

	/* Link BUFF into the send queue. */
	__skb_header_release(buff);
	tcp_insert_write_queue_after(skb, buff, sk, TCP_FRAG_IN_WRITE_QUEUE);

	return 0;
}

/* Try to defer sending, if possible, in order to minimize the amount
 * of TSO splitting we do.  View it as a kind of TSO Nagle test.
 *
 * This algorithm is from John Heffner.
 */
static bool tcp_tso_should_defer(struct sock *sk, struct sk_buff *skb,
				 bool *is_cwnd_limited,
				 bool *is_rwnd_limited,
				 u32 max_segs)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	u32 send_win, cong_win, limit, in_flight;
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *head;
	int win_divisor;
	s64 delta;

	if (icsk->icsk_ca_state >= TCP_CA_Recovery)
		goto send_now;

	/* Avoid bursty behavior by allowing defer
	 * only if the last write was recent (1 ms).
	 * Note that tp->tcp_wstamp_ns can be in the future if we have
	 * packets waiting in a qdisc or device for EDT delivery.
	 */
	delta = tp->tcp_clock_cache - tp->tcp_wstamp_ns - NSEC_PER_MSEC;
	if (delta > 0)
		goto send_now;

	in_flight = tcp_packets_in_flight(tp);

	BUG_ON(tcp_skb_pcount(skb) <= 1);
	BUG_ON(tp->snd_cwnd <= in_flight);

	send_win = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

	/* From in_flight test above, we know that cwnd > in_flight.  */
	cong_win = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	limit = min(send_win, cong_win);

	/* If a full-sized TSO skb can be sent, do it. */
	if (limit >= max_segs * tp->mss_cache)
		goto send_now;

	/* Middle in queue won't get any more data, full sendable already? */
	if ((skb != tcp_write_queue_tail(sk)) && (limit >= skb->len))
		goto send_now;

	win_divisor = READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_tso_win_divisor);
	if (win_divisor) {
		u32 chunk = min(tp->snd_wnd, tp->snd_cwnd * tp->mss_cache);

		/* If at least some fraction of a window is available,
		 * just use it.
		 */
		chunk /= win_divisor;
		if (limit >= chunk)
			goto send_now;
	} else {
		/* Different approach, try not to defer past a single
		 * ACK.  Receiver should ACK every other full sized
		 * frame, so if we have space for more than 3 frames
		 * then send now.
		 */
		if (limit > tcp_max_tso_deferred_mss(tp) * tp->mss_cache)
			goto send_now;
	}

	/* TODO : use tsorted_sent_queue ? */
	head = tcp_rtx_queue_head(sk);
	if (!head)
		goto send_now;
	delta = tp->tcp_clock_cache - head->tstamp;
	/* If next ACK is likely to come too late (half srtt), do not defer */
	if ((s64)(delta - (u64)NSEC_PER_USEC * (tp->srtt_us >> 4)) < 0)
		goto send_now;

	/* Ok, it looks like it is advisable to defer.
	 * Three cases are tracked :
	 * 1) We are cwnd-limited
	 * 2) We are rwnd-limited
	 * 3) We are application limited.
	 */
	if (cong_win < send_win) {
		if (cong_win <= skb->len) {
			*is_cwnd_limited = true;
			return true;
		}
	} else {
		if (send_win <= skb->len) {
			*is_rwnd_limited = true;
			return true;
		}
	}

	/* If this packet won't get more data, do not wait. */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) ||
	    TCP_SKB_CB(skb)->eor)
		goto send_now;

	return true;

send_now:
	return false;
}

static inline void tcp_mtu_check_reprobe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	u32 interval;
	s32 delta;

	interval = net->ipv4.sysctl_tcp_probe_interval;
	delta = tcp_jiffies32 - icsk->icsk_mtup.probe_timestamp;
	if (unlikely(delta >= interval * HZ)) {
		int mss = tcp_current_mss(sk);

		/* Update current search range */
		icsk->icsk_mtup.probe_size = 0;
		icsk->icsk_mtup.search_high = tp->rx_opt.mss_clamp +
			sizeof(struct tcphdr) +
			icsk->icsk_af_ops->net_header_len;
		icsk->icsk_mtup.search_low = tcp_mss_to_mtu(sk, mss);

		/* Update probe time stamp */
		icsk->icsk_mtup.probe_timestamp = tcp_jiffies32;
	}
}

static bool tcp_can_coalesce_send_queue_head(struct sock *sk, int len)
{
	struct sk_buff *skb, *next;

	skb = tcp_send_head(sk);
	tcp_for_write_queue_from_safe(skb, next, sk) {
		if (len <= skb->len)
			break;

		if (unlikely(TCP_SKB_CB(skb)->eor) || tcp_has_tx_tstamp(skb))
			return false;

		len -= skb->len;
	}

	return true;
}

/* Create a new MTU probe if we are ready.
 * MTU probe is regularly attempting to increase the path MTU by
 * deliberately sending larger packets.  This discovers routing
 * changes resulting in larger path MTUs.
 *
 * Returns 0 if we should wait to probe (no cwnd available),
 *         1 if a probe was sent,
 *         -1 otherwise
 */
static int tcp_mtu_probe(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *nskb, *next;
	struct net *net = sock_net(sk);
	int probe_size;
	int size_needed;
	int copy, len;
	int mss_now;
	int interval;

	/* Not currently probing/verifying,
	 * not in recovery,
	 * have enough cwnd, and
	 * not SACKing (the variable headers throw things off)
	 */
	if (likely(!icsk->icsk_mtup.enabled ||
		   icsk->icsk_mtup.probe_size ||
		   inet_csk(sk)->icsk_ca_state != TCP_CA_Open ||
		   tp->snd_cwnd < 11 ||
		   tp->rx_opt.num_sacks || tp->rx_opt.dsack))
		return -1;

	/* Use binary search for probe_size between tcp_mss_base,
	 * and current mss_clamp. if (search_high - search_low)
	 * smaller than a threshold, backoff from probing.
	 */
	mss_now = tcp_current_mss(sk);
	probe_size = tcp_mtu_to_mss(sk, (icsk->icsk_mtup.search_high +
				    icsk->icsk_mtup.search_low) >> 1);
	size_needed = probe_size + (tp->reordering + 1) * tp->mss_cache;
	interval = icsk->icsk_mtup.search_high - icsk->icsk_mtup.search_low;
	/* When misfortune happens, we are reprobing actively,
	 * and then reprobe timer has expired. We stick with current
	 * probing process by not resetting search range to its orignal.
	 */
	if (probe_size > tcp_mtu_to_mss(sk, icsk->icsk_mtup.search_high) ||
		interval < net->ipv4.sysctl_tcp_probe_threshold) {
		/* Check whether enough time has elaplased for
		 * another round of probing.
		 */
		tcp_mtu_check_reprobe(sk);
		return -1;
	}

	/* Have enough data in the send queue to probe? */
	if (tp->write_seq - tp->snd_nxt < size_needed)
		return -1;

	if (tp->snd_wnd < size_needed)
		return -1;
	if (after(tp->snd_nxt + size_needed, tcp_wnd_end(tp)))
		return 0;

	/* Do we need to wait to drain cwnd? With none in flight, don't stall */
	if (tcp_packets_in_flight(tp) + 2 > tp->snd_cwnd) {
		if (!tcp_packets_in_flight(tp))
			return -1;
		else
			return 0;
	}

	if (!tcp_can_coalesce_send_queue_head(sk, probe_size))
		return -1;

	/* We're allowed to probe.  Build it now. */
	nskb = sk_stream_alloc_skb(sk, probe_size, GFP_ATOMIC, false);
	if (!nskb)
		return -1;
	sk_wmem_queued_add(sk, nskb->truesize);
	sk_mem_charge(sk, nskb->truesize);

	skb = tcp_send_head(sk);
	skb_copy_decrypted(nskb, skb);

	TCP_SKB_CB(nskb)->seq = TCP_SKB_CB(skb)->seq;
	TCP_SKB_CB(nskb)->end_seq = TCP_SKB_CB(skb)->seq + probe_size;
	TCP_SKB_CB(nskb)->tcp_flags = TCPHDR_ACK;
	TCP_SKB_CB(nskb)->sacked = 0;
	nskb->csum = 0;
	nskb->ip_summed = CHECKSUM_PARTIAL;

	tcp_insert_write_queue_before(nskb, skb, sk);
	tcp_highest_sack_replace(sk, skb, nskb);

	len = 0;
	tcp_for_write_queue_from_safe(skb, next, sk) {
		copy = min_t(int, skb->len, probe_size - len);
		skb_copy_bits(skb, 0, skb_put(nskb, copy), copy);

		if (skb->len <= copy) {
			/* We've eaten all the data from this skb.
			 * Throw it away. */
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags;
			/* If this is the last SKB we copy and eor is set
			 * we need to propagate it to the new skb.
			 */
			TCP_SKB_CB(nskb)->eor = TCP_SKB_CB(skb)->eor;
			tcp_skb_collapse_tstamp(nskb, skb);
			tcp_unlink_write_queue(skb, sk);
			sk_wmem_free_skb(sk, skb);
		} else {
			TCP_SKB_CB(nskb)->tcp_flags |= TCP_SKB_CB(skb)->tcp_flags &
						   ~(TCPHDR_FIN|TCPHDR_PSH);
			if (!skb_shinfo(skb)->nr_frags) {
				skb_pull(skb, copy);
			} else {
				__pskb_trim_head(skb, copy);
				tcp_set_skb_tso_segs(skb, mss_now);
			}
			TCP_SKB_CB(skb)->seq += copy;
		}

		len += copy;

		if (len >= probe_size)
			break;
	}
	tcp_init_tso_segs(nskb, nskb->len);

	/* We're ready to send.  If this fails, the probe will
	 * be resegmented into mss-sized pieces by tcp_write_xmit().
	 */
	if (!tcp_transmit_skb(sk, nskb, 1, GFP_ATOMIC)) {
		/* Decrement cwnd here because we are sending
		 * effectively two packets. */
		tp->snd_cwnd--;
		tcp_event_new_data_sent(sk, nskb);

		icsk->icsk_mtup.probe_size = tcp_mss_to_mtu(sk, nskb->len);
		tp->mtu_probe.probe_seq_start = TCP_SKB_CB(nskb)->seq;
		tp->mtu_probe.probe_seq_end = TCP_SKB_CB(nskb)->end_seq;

		return 1;
	}

	return -1;
}

static bool tcp_pacing_check(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_needs_internal_pacing(sk))
		return false;

	if (tp->tcp_wstamp_ns <= tp->tcp_clock_cache)
		return false;

	if (!hrtimer_is_queued(&tp->pacing_timer)) {
		hrtimer_start(&tp->pacing_timer,
			      ns_to_ktime(tp->tcp_wstamp_ns),
			      HRTIMER_MODE_ABS_PINNED_SOFT);
		sock_hold(sk);
	}
	return true;
}

/* TCP Small Queues :
 * Control number of packets in qdisc/devices to two packets / or ~1 ms.
 * (These limits are doubled for retransmits)
 * This allows for :
 *  - better RTT estimation and ACK scheduling
 *  - faster recovery
 *  - high rates
 * Alas, some drivers / subsystems require a fair amount
 * of queued bytes to ensure line rate.
 * One example is wifi aggregation (802.11 AMPDU)
 */
static bool tcp_small_queue_check(struct sock *sk, const struct sk_buff *skb,
				  unsigned int factor)
{
	unsigned long limit;

	limit = max_t(unsigned long,
		      2 * skb->truesize,
		      sk->sk_pacing_rate >> READ_ONCE(sk->sk_pacing_shift));
	if (sk->sk_pacing_status == SK_PACING_NONE)
		limit = min_t(unsigned long, limit,
			      sock_net(sk)->ipv4.sysctl_tcp_limit_output_bytes);
	limit <<= factor;

	if (static_branch_unlikely(&tcp_tx_delay_enabled) &&
	    tcp_sk(sk)->tcp_tx_delay) {
		u64 extra_bytes = (u64)sk->sk_pacing_rate * tcp_sk(sk)->tcp_tx_delay;

		/* TSQ is based on skb truesize sum (sk_wmem_alloc), so we
		 * approximate our needs assuming an ~100% skb->truesize overhead.
		 * USEC_PER_SEC is approximated by 2^20.
		 * do_div(extra_bytes, USEC_PER_SEC/2) is replaced by a right shift.
		 */
		extra_bytes >>= (20 - 1);
		limit += extra_bytes;
	}
	if (refcount_read(&sk->sk_wmem_alloc) > limit) {
		/* Always send skb if rtx queue is empty.
		 * No need to wait for TX completion to call us back,
		 * after softirq/tasklet schedule.
		 * This helps when TX completions are delayed too much.
		 */
		if (tcp_rtx_queue_empty(sk))
			return false;

		set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);
		/* It is possible TX completion already happened
		 * before we set TSQ_THROTTLED, so we must
		 * test again the condition.
		 */
		smp_mb__after_atomic();
		if (refcount_read(&sk->sk_wmem_alloc) > limit)
			return true;
	}
	return false;
}

static void tcp_chrono_set(struct tcp_sock *tp, const enum tcp_chrono new)
{
	const u32 now = tcp_jiffies32;
	enum tcp_chrono old = tp->chrono_type;

	if (old > TCP_CHRONO_UNSPEC)
		tp->chrono_stat[old - 1] += now - tp->chrono_start;
	tp->chrono_start = now;
	tp->chrono_type = new;
}

void tcp_chrono_start(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* If there are multiple conditions worthy of tracking in a
	 * chronograph then the highest priority enum takes precedence
	 * over the other conditions. So that if something "more interesting"
	 * starts happening, stop the previous chrono and start a new one.
	 */
	if (type > tp->chrono_type)
		tcp_chrono_set(tp, type);
}

void tcp_chrono_stop(struct sock *sk, const enum tcp_chrono type)
{
	struct tcp_sock *tp = tcp_sk(sk);


	/* There are multiple conditions worthy of tracking in a
	 * chronograph, so that the highest priority enum takes
	 * precedence over the other conditions (see tcp_chrono_start).
	 * If a condition stops, we only stop chrono tracking if
	 * it's the "most interesting" or current chrono we are
	 * tracking and starts busy chrono if we have pending data.
	 */
	if (tcp_rtx_and_write_queues_empty(sk))
		tcp_chrono_set(tp, TCP_CHRONO_UNSPEC);
	else if (type == tp->chrono_type)
		tcp_chrono_set(tp, TCP_CHRONO_BUSY);
}

/* This routine writes packets to the network.  It advances the
 * send_head.  This happens as incoming acks open up the remote
 * window for us.
 *
 * LARGESEND note: !tcp_urg_mode is overkill, only frames between
 * snd_up-64k-mss .. snd_up cannot be large. However, taking into
 * account rare use of URG, this is not a big flaw.
 *
 * Send at most one packet when push_one > 0. Temporarily ignore
 * cwnd limit to force at most one packet out when push_one == 2.

 * Returns true, if no segments are in flight and we have queued segments,
 * but cannot send anything now because of SWS or another problem.
 */
static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,
			   int push_one, gfp_t gfp)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	unsigned int tso_segs, sent_pkts;
	int cwnd_quota;
	int result;
	bool is_cwnd_limited = false, is_rwnd_limited = false;
	u32 max_segs;

	sent_pkts = 0;

	tcp_mstamp_refresh(tp);
	if (!push_one) {
		/* Do MTU probing. */
		result = tcp_mtu_probe(sk);
		if (!result) {
			return false;
		} else if (result > 0) {
			sent_pkts = 1;
		}
	}

	max_segs = tcp_tso_segs(sk, mss_now);
	while ((skb = tcp_send_head(sk))) {
		unsigned int limit;

		if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {
			/* "skb_mstamp_ns" is used as a start point for the retransmit timer */
			skb->skb_mstamp_ns = tp->tcp_wstamp_ns = tp->tcp_clock_cache;
			list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);
			tcp_init_tso_segs(skb, mss_now);
			goto repair; /* Skip network transmission */
		}

		if (tcp_pacing_check(sk))
			break;

		tso_segs = tcp_init_tso_segs(skb, mss_now);
		BUG_ON(!tso_segs);

		cwnd_quota = tcp_cwnd_test(tp, skb);
		if (!cwnd_quota) {
			if (push_one == 2)
				/* Force out a loss probe pkt. */
				cwnd_quota = 1;
			else
				break;
		}

		if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {
			is_rwnd_limited = true;
			break;
		}

		if (tso_segs == 1) {
			if (unlikely(!tcp_nagle_test(tp, skb, mss_now,
						     (tcp_skb_is_last(sk, skb) ?
						      nonagle : TCP_NAGLE_PUSH))))
				break;
		} else {
			if (!push_one &&
			    tcp_tso_should_defer(sk, skb, &is_cwnd_limited,
						 &is_rwnd_limited, max_segs))
				break;
		}

		limit = mss_now;
		if (tso_segs > 1 && !tcp_urg_mode(tp))
			limit = tcp_mss_split_point(sk, skb, mss_now,
						    min_t(unsigned int,
							  cwnd_quota,
							  max_segs),
						    nonagle);

		if (skb->len > limit &&
		    unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))
			break;

		if (tcp_small_queue_check(sk, skb, 0))
			break;

		/* Argh, we hit an empty skb(), presumably a thread
		 * is sleeping in sendmsg()/sk_stream_wait_memory().
		 * We do not want to send a pure-ack packet and have
		 * a strange looking rtx queue with empty packet(s).
		 */
		if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)
			break;

		if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))
			break;

repair:
		/* Advance the send_head.  This one is sent out.
		 * This call will increment packets_out.
		 */
		tcp_event_new_data_sent(sk, skb);

		tcp_minshall_update(tp, mss_now, skb);
		sent_pkts += tcp_skb_pcount(skb);

		if (push_one)
			break;
	}

	if (is_rwnd_limited)
		tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);
	else
		tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);

	if (likely(sent_pkts)) {
		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += sent_pkts;

		/* Send one loss probe per tail loss episode. */
		if (push_one != 2)
			tcp_schedule_loss_probe(sk, false);
		is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tp->snd_cwnd);
		tcp_cwnd_validate(sk, is_cwnd_limited);
		return false;
	}
	return !tp->packets_out && !tcp_write_queue_empty(sk);
}

bool tcp_schedule_loss_probe(struct sock *sk, bool advancing_rto)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, rto_delta_us;
	int early_retrans;

	/* Don't do any loss probe on a Fast Open connection before 3WHS
	 * finishes.
	 */
	if (rcu_access_pointer(tp->fastopen_rsk))
		return false;

	early_retrans = sock_net(sk)->ipv4.sysctl_tcp_early_retrans;
	/* Schedule a loss probe in 2*RTT for SACK capable connections
	 * not in loss recovery, that are either limited by cwnd or application.
	 */
	if ((early_retrans != 3 && early_retrans != 4) ||
	    !tp->packets_out || !tcp_is_sack(tp) ||
	    (icsk->icsk_ca_state != TCP_CA_Open &&
	     icsk->icsk_ca_state != TCP_CA_CWR))
		return false;

	/* Probe timeout is 2*rtt. Add minimum RTO to account
	 * for delayed ack when there's one outstanding packet. If no RTT
	 * sample is available then probe after TCP_TIMEOUT_INIT.
	 */
	if (tp->srtt_us) {
		timeout = usecs_to_jiffies(tp->srtt_us >> 2);
		if (tp->packets_out == 1)
			timeout += TCP_RTO_MIN;
		else
			timeout += TCP_TIMEOUT_MIN;
	} else {
		timeout = TCP_TIMEOUT_INIT;
	}

	/* If the RTO formula yields an earlier time, then use that time. */
	rto_delta_us = advancing_rto ?
			jiffies_to_usecs(inet_csk(sk)->icsk_rto) :
			tcp_rto_delta_us(sk);  /* How far in future is RTO? */
	if (rto_delta_us > 0)
		timeout = min_t(u32, timeout, usecs_to_jiffies(rto_delta_us));

	tcp_reset_xmit_timer(sk, ICSK_TIME_LOSS_PROBE, timeout,
			     TCP_RTO_MAX, NULL);
	return true;
}

/* Thanks to skb fast clones, we can detect if a prior transmit of
 * a packet is still in a qdisc or driver queue.
 * In this case, there is very little point doing a retransmit !
 */
static bool skb_still_in_host_queue(const struct sock *sk,
				    const struct sk_buff *skb)
{
	if (unlikely(skb_fclone_busy(sk, skb))) {
		NET_INC_STATS(sock_net(sk),
			      LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES);
		return true;
	}
	return false;
}

/* When probe timeout (PTO) fires, try send a new segment if possible, else
 * retransmit the last segment.
 */
void tcp_send_loss_probe(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;
	int pcount;
	int mss = tcp_current_mss(sk);

	skb = tcp_send_head(sk);
	if (skb && tcp_snd_wnd_test(tp, skb, mss)) {
		pcount = tp->packets_out;
		tcp_write_xmit(sk, mss, TCP_NAGLE_OFF, 2, GFP_ATOMIC);
		if (tp->packets_out > pcount)
			goto probe_sent;
		goto rearm_timer;
	}
	skb = skb_rb_last(&sk->tcp_rtx_queue);
	if (unlikely(!skb)) {
		WARN_ONCE(tp->packets_out,
			  "invalid inflight: %u state %u cwnd %u mss %d\n",
			  tp->packets_out, sk->sk_state, tp->snd_cwnd, mss);
		inet_csk(sk)->icsk_pending = 0;
		return;
	}

	/* At most one outstanding TLP retransmission. */
	if (tp->tlp_high_seq)
		goto rearm_timer;

	if (skb_still_in_host_queue(sk, skb))
		goto rearm_timer;

	pcount = tcp_skb_pcount(skb);
	if (WARN_ON(!pcount))
		goto rearm_timer;

	if ((pcount > 1) && (skb->len > (pcount - 1) * mss)) {
		if (unlikely(tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
					  (pcount - 1) * mss, mss,
					  GFP_ATOMIC)))
			goto rearm_timer;
		skb = skb_rb_next(skb);
	}

	if (WARN_ON(!skb || !tcp_skb_pcount(skb)))
		goto rearm_timer;

	if (__tcp_retransmit_skb(sk, skb, 1))
		goto rearm_timer;

	/* Record snd_nxt for loss detection. */
	tp->tlp_high_seq = tp->snd_nxt;

probe_sent:
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPLOSSPROBES);
	/* Reset s.t. tcp_rearm_rto will restart timer from now */
	inet_csk(sk)->icsk_pending = 0;
rearm_timer:
	tcp_rearm_rto(sk);
}

/* Push out any pending frames which were held back due to
 * TCP_CORK or attempt at coalescing tiny packets.
 * The socket must be locked by the caller.
 */
void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,
			       int nonagle)
{
	/* If we are closed, the bytes will have to remain here.
	 * In time closedown will finish, we empty the write queue and
	 * all will be happy.
	 */
	if (unlikely(sk->sk_state == TCP_CLOSE))
		return;

	if (tcp_write_xmit(sk, cur_mss, nonagle, 0,
			   sk_gfp_mask(sk, GFP_ATOMIC)))
		tcp_check_probe_timer(sk);
}

/* Send _single_ skb sitting at the send head. This function requires
 * true push pending frames to setup probe timer etc.
 */
void tcp_push_one(struct sock *sk, unsigned int mss_now)
{
	struct sk_buff *skb = tcp_send_head(sk);

	BUG_ON(!skb || skb->len < mss_now);

	tcp_write_xmit(sk, mss_now, TCP_NAGLE_PUSH, 1, sk->sk_allocation);
}

/* This function returns the amount that we can raise the
 * usable window based on the following constraints
 *
 * 1. The window can never be shrunk once it is offered (RFC 793)
 * 2. We limit memory per socket
 *
 * RFC 1122:
 * "the suggested [SWS] avoidance algorithm for the receiver is to keep
 *  RECV.NEXT + RCV.WIN fixed until:
 *  RCV.BUFF - RCV.USER - RCV.WINDOW >= min(1/2 RCV.BUFF, MSS)"
 *
 * i.e. don't raise the right edge of the window until you can raise
 * it at least MSS bytes.
 *
 * Unfortunately, the recommended algorithm breaks header prediction,
 * since header prediction assumes th->window stays fixed.
 *
 * Strictly speaking, keeping th->window fixed violates the receiver
 * side SWS prevention criteria. The problem is that under this rule
 * a stream of single byte packets will cause the right side of the
 * window to always advance by a single byte.
 *
 * Of course, if the sender implements sender side SWS prevention
 * then this will not be a problem.
 *
 * BSD seems to make the following compromise:
 *
 *	If the free space is less than the 1/4 of the maximum
 *	space available and the free space is less than 1/2 mss,
 *	then set the window to 0.
 *	[ Actually, bsd uses MSS and 1/4 of maximal _window_ ]
 *	Otherwise, just prevent the window from shrinking
 *	and from being larger than the largest representable value.
 *
 * This prevents incremental opening of the window in the regime
 * where TCP is limited by the speed of the reader side taking
 * data out of the TCP receive queue. It does nothing about
 * those cases where the window is constrained on the sender side
 * because the pipeline is full.
 *
 * BSD also seems to "accidentally" limit itself to windows that are a
 * multiple of MSS, at least until the free space gets quite small.
 * This would appear to be a side effect of the mbuf implementation.
 * Combining these two algorithms results in the observed behavior
 * of having a fixed window size at almost all times.
 *
 * Below we obtain similar behavior by forcing the offered window to
 * a multiple of the mss when it is feasible to do so.
 *
 * Note, we don't "adjust" for TIMESTAMP or SACK option bytes.
 * Regular options like TIMESTAMP are taken into account.
 */
u32 __tcp_select_window(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	/* MSS for the peer's data.  Previous versions used mss_clamp
	 * here.  I don't know if the value based on our guesses
	 * of peer's MSS is better for the performance.  It's more correct
	 * but may be worse for the performance because of rcv_mss
	 * fluctuations.  --SAW  1998/11/1
	 */
	int mss = icsk->icsk_ack.rcv_mss;
	int free_space = tcp_space(sk);
	int allowed_space = tcp_full_space(sk);
	int full_space = min_t(int, tp->window_clamp, allowed_space);
	int window;

	if (unlikely(mss > full_space)) {
		mss = full_space;
		if (mss <= 0)
			return 0;
	}
	if (free_space < (full_space >> 1)) {
		icsk->icsk_ack.quick = 0;

		if (tcp_under_memory_pressure(sk))
			tp->rcv_ssthresh = min(tp->rcv_ssthresh,
					       4U * tp->advmss);

		/* free_space might become our new window, make sure we don't
		 * increase it due to wscale.
		 */
		free_space = round_down(free_space, 1 << tp->rx_opt.rcv_wscale);

		/* if free space is less than mss estimate, or is below 1/16th
		 * of the maximum allowed, try to move to zero-window, else
		 * tcp_clamp_window() will grow rcv buf up to tcp_rmem[2], and
		 * new incoming data is dropped due to memory limits.
		 * With large window, mss test triggers way too late in order
		 * to announce zero window in time before rmem limit kicks in.
		 */
		if (free_space < (allowed_space >> 4) || free_space < mss)
			return 0;
	}

	if (free_space > tp->rcv_ssthresh)
		free_space = tp->rcv_ssthresh;

	/* Don't do rounding if we are using window scaling, since the
	 * scaled window will not line up with the MSS boundary anyway.
	 */
	if (tp->rx_opt.rcv_wscale) {
		window = free_space;

		/* Advertise enough space so that it won't get scaled away.
		 * Import case: prevent zero window announcement if
		 * 1<<rcv_wscale > mss.
		 */
		window = ALIGN(window, (1 << tp->rx_opt.rcv_wscale));
	} else {
		window = tp->rcv_wnd;
		/* Get the largest window that is a nice multiple of mss.
		 * Window clamp already applied above.
		 * If our current window offering is within 1 mss of the
		 * free space we just keep it. This prevents the divide
		 * and multiply from happening most of the time.
		 * We also don't do any window rounding when the free space
		 * is too small.
		 */
		if (window <= free_space - mss || window > free_space)
			window = rounddown(free_space, mss);
		else if (mss == full_space &&
			 free_space > window + (full_space >> 1))
			window = free_space;
	}

	return window;
}

void tcp_skb_collapse_tstamp(struct sk_buff *skb,
			     const struct sk_buff *next_skb)
{
	if (unlikely(tcp_has_tx_tstamp(next_skb))) {
		const struct skb_shared_info *next_shinfo =
			skb_shinfo(next_skb);
		struct skb_shared_info *shinfo = skb_shinfo(skb);

		shinfo->tx_flags |= next_shinfo->tx_flags & SKBTX_ANY_TSTAMP;
		shinfo->tskey = next_shinfo->tskey;
		TCP_SKB_CB(skb)->txstamp_ack |=
			TCP_SKB_CB(next_skb)->txstamp_ack;
	}
}

/* Collapses two adjacent SKB's during retransmission. */
static bool tcp_collapse_retrans(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *next_skb = skb_rb_next(skb);
	int next_skb_size;

	next_skb_size = next_skb->len;

	BUG_ON(tcp_skb_pcount(skb) != 1 || tcp_skb_pcount(next_skb) != 1);

	if (next_skb_size) {
		if (next_skb_size <= skb_availroom(skb))
			skb_copy_bits(next_skb, 0, skb_put(skb, next_skb_size),
				      next_skb_size);
		else if (!tcp_skb_shift(skb, next_skb, 1, next_skb_size))
			return false;
	}
	tcp_highest_sack_replace(sk, next_skb, skb);

	/* Update sequence range on original skb. */
	TCP_SKB_CB(skb)->end_seq = TCP_SKB_CB(next_skb)->end_seq;

	/* Merge over control information. This moves PSH/FIN etc. over */
	TCP_SKB_CB(skb)->tcp_flags |= TCP_SKB_CB(next_skb)->tcp_flags;

	/* All done, get rid of second SKB and account for it so
	 * packet counting does not break.
	 */
	TCP_SKB_CB(skb)->sacked |= TCP_SKB_CB(next_skb)->sacked & TCPCB_EVER_RETRANS;
	TCP_SKB_CB(skb)->eor = TCP_SKB_CB(next_skb)->eor;

	/* changed transmit queue under us so clear hints */
	tcp_clear_retrans_hints_partial(tp);
	if (next_skb == tp->retransmit_skb_hint)
		tp->retransmit_skb_hint = skb;

	tcp_adjust_pcount(sk, next_skb, tcp_skb_pcount(next_skb));

	tcp_skb_collapse_tstamp(skb, next_skb);

	tcp_rtx_queue_unlink_and_free(next_skb, sk);
	return true;
}

/* Check if coalescing SKBs is legal. */
static bool tcp_can_collapse(const struct sock *sk, const struct sk_buff *skb)
{
	if (tcp_skb_pcount(skb) > 1)
		return false;
	if (skb_cloned(skb))
		return false;
	/* Some heuristics for collapsing over SACK'd could be invented */
	if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_ACKED)
		return false;

	return true;
}

/* Collapse packets in the retransmit queue to make to create
 * less packets on the wire. This is only done on retransmission.
 */
static void tcp_retrans_try_collapse(struct sock *sk, struct sk_buff *to,
				     int space)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb = to, *tmp;
	bool first = true;

	if (!sock_net(sk)->ipv4.sysctl_tcp_retrans_collapse)
		return;
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		return;

	skb_rbtree_walk_from_safe(skb, tmp) {
		if (!tcp_can_collapse(sk, skb))
			break;

		if (!tcp_skb_can_collapse(to, skb))
			break;

		space -= skb->len;

		if (first) {
			first = false;
			continue;
		}

		if (space < 0)
			break;

		if (after(TCP_SKB_CB(skb)->end_seq, tcp_wnd_end(tp)))
			break;

		if (!tcp_collapse_retrans(sk, to))
			break;
	}
}

/* This retransmits one SKB.  Policy decisions and retransmit queue
 * state updates are done by the caller.  Returns non-zero if an
 * error occurred which prevented the send.
 */
int __tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int cur_mss;
	int diff, len, err;


	/* Inconclusive MTU probe */
	if (icsk->icsk_mtup.probe_size)
		icsk->icsk_mtup.probe_size = 0;

	/* Do not sent more than we queued. 1/4 is reserved for possible
	 * copying overhead: fragmentation, tunneling, mangling etc.
	 */
	if (refcount_read(&sk->sk_wmem_alloc) >
	    min_t(u32, sk->sk_wmem_queued + (sk->sk_wmem_queued >> 2),
		  sk->sk_sndbuf))
		return -EAGAIN;

	if (skb_still_in_host_queue(sk, skb))
		return -EBUSY;

	if (before(TCP_SKB_CB(skb)->seq, tp->snd_una)) {
		if (unlikely(before(TCP_SKB_CB(skb)->end_seq, tp->snd_una))) {
			WARN_ON_ONCE(1);
			return -EINVAL;
		}
		if (tcp_trim_head(sk, skb, tp->snd_una - TCP_SKB_CB(skb)->seq))
			return -ENOMEM;
	}

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	cur_mss = tcp_current_mss(sk);

	/* If receiver has shrunk his window, and skb is out of
	 * new window, do not retransmit it. The exception is the
	 * case, when window is shrunk to zero. In this case
	 * our retransmit serves as a zero window probe.
	 */
	if (!before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp)) &&
	    TCP_SKB_CB(skb)->seq != tp->snd_una)
		return -EAGAIN;

	len = cur_mss * segs;
	if (skb->len > len) {
		if (tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb, len,
				 cur_mss, GFP_ATOMIC))
			return -ENOMEM; /* We'll try again later. */
	} else {
		if (skb_unclone(skb, GFP_ATOMIC))
			return -ENOMEM;

		diff = tcp_skb_pcount(skb);
		tcp_set_skb_tso_segs(skb, cur_mss);
		diff -= tcp_skb_pcount(skb);
		if (diff)
			tcp_adjust_pcount(sk, skb, diff);
		if (skb->len < cur_mss)
			tcp_retrans_try_collapse(sk, skb, cur_mss);
	}

	/* RFC3168, section 6.1.1.1. ECN fallback */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN_ECN) == TCPHDR_SYN_ECN)
		tcp_ecn_clear_syn(sk, skb);

	/* Update global and local TCP statistics. */
	segs = tcp_skb_pcount(skb);
	TCP_ADD_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS, segs);
	if (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
	tp->total_retrans += segs;
	tp->bytes_retrans += skb->len;

	/* make sure skb->data is aligned on arches that require it
	 * and check if ack-trimming & collapsing extended the headroom
	 * beyond what csum_start can cover.
	 */
	if (unlikely((NET_IP_ALIGN && ((unsigned long)skb->data & 3)) ||
		     skb_headroom(skb) >= 0xFFFF)) {
		struct sk_buff *nskb;

		tcp_skb_tsorted_save(skb) {
			nskb = __pskb_copy(skb, MAX_TCP_HEADER, GFP_ATOMIC);
			if (nskb) {
				nskb->dev = NULL;
				err = tcp_transmit_skb(sk, nskb, 0, GFP_ATOMIC);
			} else {
				err = -ENOBUFS;
			}
		} tcp_skb_tsorted_restore(skb);

		if (!err) {
			tcp_update_skb_after_send(sk, skb, tp->tcp_wstamp_ns);
			tcp_rate_skb_sent(sk, skb);
		}
	} else {
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
	}

	/* To avoid taking spuriously low RTT samples based on a timestamp
	 * for a transmit that never happened, always mark EVER_RETRANS
	 */
	TCP_SKB_CB(skb)->sacked |= TCPCB_EVER_RETRANS;

	if (BPF_SOCK_OPS_TEST_FLAG(tp, BPF_SOCK_OPS_RETRANS_CB_FLAG))
		tcp_call_bpf_3arg(sk, BPF_SOCK_OPS_RETRANS_CB,
				  TCP_SKB_CB(skb)->seq, segs, err);

	if (likely(!err)) {
		trace_tcp_retransmit_skb(sk, skb);
	} else if (err != -EBUSY) {
		NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPRETRANSFAIL, segs);
	}
	return err;
}

int tcp_retransmit_skb(struct sock *sk, struct sk_buff *skb, int segs)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int err = __tcp_retransmit_skb(sk, skb, segs);

	if (err == 0) {
#if FASTRETRANS_DEBUG > 0
		if (TCP_SKB_CB(skb)->sacked & TCPCB_SACKED_RETRANS) {
			net_dbg_ratelimited("retrans_out leaked\n");
		}
#endif
		TCP_SKB_CB(skb)->sacked |= TCPCB_RETRANS;
		tp->retrans_out += tcp_skb_pcount(skb);
	}

	/* Save stamp of the first (attempted) retransmit. */
	if (!tp->retrans_stamp)
		tp->retrans_stamp = tcp_skb_timestamp(skb);

	if (tp->undo_retrans < 0)
		tp->undo_retrans = 0;
	tp->undo_retrans += tcp_skb_pcount(skb);
	return err;
}

/* This gets called after a retransmit timeout, and the initially
 * retransmitted data is acknowledged.  It tries to continue
 * resending the rest of the retransmit queue, until either
 * we've sent it all or the congestion window limit is reached.
 */
void tcp_xmit_retransmit_queue(struct sock *sk)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct sk_buff *skb, *rtx_head, *hole = NULL;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 max_segs;
	int mib_idx;

	if (!tp->packets_out)
		return;

	rtx_head = tcp_rtx_queue_head(sk);
	skb = tp->retransmit_skb_hint ?: rtx_head;
	max_segs = tcp_tso_segs(sk, tcp_current_mss(sk));
	skb_rbtree_walk_from(skb) {
		__u8 sacked;
		int segs;

		if (tcp_pacing_check(sk))
			break;

		/* we could do better than to assign each time */
		if (!hole)
			tp->retransmit_skb_hint = skb;

		segs = tp->snd_cwnd - tcp_packets_in_flight(tp);
		if (segs <= 0)
			return;
		sacked = TCP_SKB_CB(skb)->sacked;
		/* In case tcp_shift_skb_data() have aggregated large skbs,
		 * we need to make sure not sending too bigs TSO packets
		 */
		segs = min_t(int, segs, max_segs);

		if (tp->retrans_out >= tp->lost_out) {
			break;
		} else if (!(sacked & TCPCB_LOST)) {
			if (!hole && !(sacked & (TCPCB_SACKED_RETRANS|TCPCB_SACKED_ACKED)))
				hole = skb;
			continue;

		} else {
			if (icsk->icsk_ca_state != TCP_CA_Loss)
				mib_idx = LINUX_MIB_TCPFASTRETRANS;
			else
				mib_idx = LINUX_MIB_TCPSLOWSTARTRETRANS;
		}

		if (sacked & (TCPCB_SACKED_ACKED|TCPCB_SACKED_RETRANS))
			continue;

		if (tcp_small_queue_check(sk, skb, 1))
			return;

		if (tcp_retransmit_skb(sk, skb, segs))
			return;

		NET_ADD_STATS(sock_net(sk), mib_idx, tcp_skb_pcount(skb));

		if (tcp_in_cwnd_reduction(sk))
			tp->prr_out += tcp_skb_pcount(skb);

		if (skb == rtx_head &&
		    icsk->icsk_pending != ICSK_TIME_REO_TIMEOUT)
			tcp_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
					     inet_csk(sk)->icsk_rto,
					     TCP_RTO_MAX,
					     skb);
	}
}

/* We allow to exceed memory limits for FIN packets to expedite
 * connection tear down and (memory) recovery.
 * Otherwise tcp_send_fin() could be tempted to either delay FIN
 * or even be forced to close flow without any FIN.
 * In general, we want to allow one skb per socket to avoid hangs
 * with edge trigger epoll()
 */
void sk_forced_mem_schedule(struct sock *sk, int size)
{
	int amt;

	if (size <= sk->sk_forward_alloc)
		return;
	amt = sk_mem_pages(size);
	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;
	sk_memory_allocated_add(sk, amt);

	if (mem_cgroup_sockets_enabled && sk->sk_memcg)
		mem_cgroup_charge_skmem(sk->sk_memcg, amt);
}

/* Send a FIN. The caller locks the socket for us.
 * We should try to send a FIN packet really hard, but eventually give up.
 */
void tcp_send_fin(struct sock *sk)
{
	struct sk_buff *skb, *tskb, *tail = tcp_write_queue_tail(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	/* Optimization, tack on the FIN if we have one skb in write queue and
	 * this skb was not yet sent, or we are under memory pressure.
	 * Note: in the latter case, FIN packet will be sent after a timeout,
	 * as TCP stack thinks it has already been transmitted.
	 */
	tskb = tail;
	if (!tskb && tcp_under_memory_pressure(sk))
		tskb = skb_rb_last(&sk->tcp_rtx_queue);

	if (tskb) {
		TCP_SKB_CB(tskb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(tskb)->end_seq++;
		tp->write_seq++;
		if (!tail) {
			/* This means tskb was already sent.
			 * Pretend we included the FIN on previous transmit.
			 * We need to set tp->snd_nxt to the value it would have
			 * if FIN had been sent. This is because retransmit path
			 * does not change tp->snd_nxt.
			 */
			WRITE_ONCE(tp->snd_nxt, tp->snd_nxt + 1);
			return;
		}
	} else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, sk->sk_allocation);
		if (unlikely(!skb))
			return;

		INIT_LIST_HEAD(&skb->tcp_tsorted_anchor);
		skb_reserve(skb, MAX_TCP_HEADER);
		sk_forced_mem_schedule(sk, skb->truesize);
		/* FIN eats a sequence byte, write_seq advanced by tcp_queue_skb(). */
		tcp_init_nondata_skb(skb, tp->write_seq,
				     TCPHDR_ACK | TCPHDR_FIN);
		tcp_queue_skb(sk, skb);
	}
	__tcp_push_pending_frames(sk, tcp_current_mss(sk), TCP_NAGLE_OFF);
}

/* We get here when a process closes a file descriptor (either due to
 * an explicit close() or as a byproduct of exit()'ing) and there
 * was unread data in the receive queue.  This behavior is recommended
 * by RFC 2525, section 2.17.  -DaveM
 */
void tcp_send_active_reset(struct sock *sk, gfp_t priority)
{
	struct sk_buff *skb;

	TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTRSTS);

	/* NOTE: No TCP options attached and we never retransmit this. */
	skb = alloc_skb(MAX_TCP_HEADER, priority);
	if (!skb) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);
		return;
	}

	/* Reserve space for headers and prepare control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	tcp_init_nondata_skb(skb, tcp_acceptable_seq(sk),
			     TCPHDR_ACK | TCPHDR_RST);
	tcp_mstamp_refresh(tcp_sk(sk));
	/* Send it off. */
	if (tcp_transmit_skb(sk, skb, 0, priority))
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPABORTFAILED);

	/* skb of trace_tcp_send_reset() keeps the skb that caused RST,
	 * skb here is different to the troublesome skb, so use NULL
	 */
	trace_tcp_send_reset(sk, NULL);
}

/* Send a crossed SYN-ACK during socket establishment.
 * WARNING: This routine must only be called when we have already sent
 * a SYN packet that crossed the incoming SYN that caused this routine
 * to get called. If this assumption fails then the initial rcv_wnd
 * and rcv_wscale values will not be correct.
 */
int tcp_send_synack(struct sock *sk)
{
	struct sk_buff *skb;

	skb = tcp_rtx_queue_head(sk);
	if (!skb || !(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_SYN)) {
		pr_err("%s: wrong queue state\n", __func__);
		return -EFAULT;
	}
	if (!(TCP_SKB_CB(skb)->tcp_flags & TCPHDR_ACK)) {
		if (skb_cloned(skb)) {
			struct sk_buff *nskb;

			tcp_skb_tsorted_save(skb) {
				nskb = skb_copy(skb, GFP_ATOMIC);
			} tcp_skb_tsorted_restore(skb);
			if (!nskb)
				return -ENOMEM;
			INIT_LIST_HEAD(&nskb->tcp_tsorted_anchor);
			tcp_highest_sack_replace(sk, skb, nskb);
			tcp_rtx_queue_unlink_and_free(skb, sk);
			__skb_header_release(nskb);
			tcp_rbtree_insert(&sk->tcp_rtx_queue, nskb);
			sk_wmem_queued_add(sk, nskb->truesize);
			sk_mem_charge(sk, nskb->truesize);
			skb = nskb;
		}

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_ACK;
		tcp_ecn_send_synack(sk, skb);
	}
	return tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
}

// 构建一个 TCP SYN-ACK 数据包，并返回一个 sk_buff（socket buffer）。
// 它用于生成 TCP 三次握手过程中的 SYN-ACK 包
// 参数介绍：
// sk 是监听套接字（即服务器端的套接字）。
// dst 是指向目标路由条目的指针，它附加到 SYN-ACK 数据包上。
// req 是指向 request_sock 结构的指针，表示当前正在处理的连接请求。
struct sk_buff *tcp_make_synack(const struct sock *sk, struct dst_entry *dst,
				struct request_sock *req,
				struct tcp_fastopen_cookie *foc,
				enum tcp_synack_type synack_type)
{	// 将 request_sock 结构 req 转换为 inet_request_sock 结构。
	struct inet_request_sock *ireq = inet_rsk(req);
	// 将 sk（监听套接字）转换为 tcp_sock 结构，获取当前套接字的 TCP 状态信息。tcp_sk 是用于访问 TCP 套接字内部结构的宏。
	const struct tcp_sock *tp = tcp_sk(sk);
	// 声明一个指针 md5，用于存储 TCP MD5 签名密钥（如果启用的话）。该密钥用于验证数据包的完整性，防止篡改。
	struct tcp_md5sig_key *md5 = NULL;
	// 存储 TCP 数据包的选项信息
	struct tcp_out_options opts;
	// 存储构建的 SYN-ACK 数据包
	struct sk_buff *skb;
	// 存储计算出的 TCP 头部大小
	int tcp_header_size;
	// 指向 tcphdr（TCP 头部）结构的指针。这个指针将用来操作 SYN-ACK 数据包的 TCP 头部。
	struct tcphdr *th;
	// 用于存储最大报文段大小（Maximum Segment Size）	
	int mss;
	// u64 类型的变量 now，用于存储当前的时间戳。
	u64 now;

	// 调用 alloc_skb 函数分配一个大小为 MAX_TCP_HEADER 的 sk_buff（socket buffer）内存。
	// 如果分配失败（skb 为 NULL），则释放目标路由条目 dst 并返回 NULL，表示失败。
	skb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (unlikely(!skb)) {
		dst_release(dst);
		return NULL;
	}
	// 为 skb 保留空间以存储 TCP 头部。skb_reserve 会调整 skb 的头部指针，确保有足够的空间来存放 TCP 头部。
	skb_reserve(skb, MAX_TCP_HEADER);

	// 根据 synack_type（SYN-ACK 类型）决定如何设置 skb 的拥有者。
	switch (synack_type) {
	case TCP_SYNACK_NORMAL:
		// skb_set_owner_w 设置当前 skb 的拥有者：
		// TCP_SYNACK_NORMAL：设置拥有者为与请求相关的套接字
		skb_set_owner_w(skb, req_to_sk(req));
		break;
	case TCP_SYNACK_COOKIE:
		// TCP_SYNACK_COOKIE：不设置拥有者，因为在 SYN flood 攻击中，防止共享。
		break;
	case TCP_SYNACK_FASTOPEN:
		// TCP_SYNACK_FASTOPEN：设置拥有者为监听套接字 sk。
		skb_set_owner_w(skb, (struct sock *)sk);
		break;
	}
	// 将目标路由条目 dst 绑定到 skb。这告诉网络层将数据包发送到哪个目的地。
	skb_dst_set(skb, dst);

	// 计算最大报文段大小（MSS），调用 tcp_mss_clamp 函数对 MSS 进行限制，
	// tcp_mss_clamp它根据目标网络的最大传输单元（MTU）来调整 MSS，确保传输的数据包不会超过网络链路的最大可传输大小
	// dst_metric_advmss(dst) 提供目标路由的最大 MSS
	mss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	// 清空 opts 结构，确保其中没有未初始化的数据
	memset(&opts, 0, sizeof(opts));
	// 获取当前时间戳，单位为纳秒
	now = tcp_clock_ns();
//设置 skb 的时间戳。如果启用了 SYN cookie（CONFIG_SYN_COOKIES），则通过 cookie_init_timestamp 函数初始化时间戳。否则，直接使用当前时间戳。
#ifdef CONFIG_SYN_COOKIES
	if (unlikely(req->cookie_ts))
		// 启用了 SYN cookie（CONFIG_SYN_COOKIES），则通过 cookie_init_timestamp 函数初始化时间戳
		skb->skb_mstamp_ns = cookie_init_timestamp(req, now);
	else
#endif
	{	//将 skb_mstamp_ns 字段设置为当前的时间戳 now
		skb->skb_mstamp_ns = now;
		// 如果 req（即请求套接字）中的 snt_synack 字段还没有设置（即为 0 或 NULL），就为它分配一个时间戳。
		if (!tcp_rsk(req)->snt_synack) 
			tcp_rsk(req)->snt_synack = tcp_skb_timestamp_us(skb);
	}

//如果启用了 TCP MD5 签名（CONFIG_TCP_MD5SIG），则通过 req_md5_lookup 获取 MD5 密钥。
#ifdef CONFIG_TCP_MD5SIG
	// rcu_read_lock 上锁用于保护 RCU 数据访问
	rcu_read_lock();
	md5 = tcp_rsk(req)->af_specific->req_md5_lookup(sk, req_to_sk(req));
#endif
	// 为skb设置TCP的 hash 值，方便后请求放入对应队列用于负载均衡
	skb_set_hash(skb, tcp_rsk(req)->txhash, PKT_HASH_TYPE_L4);
	// 调用tcp_synack_options 函数生成SYN-ACK数据包的选项，返回的tcp_header_size包括TCP头部和选项的总大小。
	tcp_header_size = tcp_synack_options(sk, req, mss, skb, &opts, md5,
					     foc) + sizeof(*th);

	//通过 skb_push 将 TCP 头部推入 skb，并重置传输层头部指针
	skb_push(skb, tcp_header_size);
	skb_reset_transport_header(skb);

	//设置 skb 的 TCP 头部。首先将其清零，然后设置 SYN 和 ACK 标志位，表示这是一个 SYN-ACK 包
	th = (struct tcphdr *)skb->data;
	memset(th, 0, sizeof(struct tcphdr));
	th->syn = 1;
	th->ack = 1;
	// 设置 ECN（显式拥塞通知）相关的选项
	tcp_ecn_make_synack(req, th);
	// 设置源端口和目的端口，ireq->ir_num 是源端口，ireq->ir_rmt_port 是目标端口
	th->source = htons(ireq->ir_num);
	th->dest = ireq->ir_rmt_port;
	// 设置 skb 的标记字段和校验和字段。CHECKSUM_PARTIAL 表示只计算部分校验和
	skb->mark = ireq->ir_mark;
	skb->ip_summed = CHECKSUM_PARTIAL;
	// 设置序列号和确认号。snt_isn 是发送的初始序列号，rcv_nxt 是接收到的下一个序列号
	th->seq = htonl(tcp_rsk(req)->snt_isn);
	th->ack_seq = htonl(tcp_rsk(req)->rcv_nxt);

	// 设置窗口大小。根据接收窗口大小和 65535 的最小值来设置
	th->window = htons(min(req->rsk_rcv_wnd, 65535U));
	// 写入 TCP 选项到 TCP 头部之后的地方
	tcp_options_write((__be32 *)(th + 1), NULL, &opts);
	//设置 TCP 头部的长度
	th->doff = (tcp_header_size >> 2);
	// 更新 TCP 输出段统计
	__TCP_INC_STATS(sock_net(sk), TCP_MIB_OUTSEGS);

// 检查是否启用了 TCP MD5 签名功能，启用了则执行以下代码
#ifdef CONFIG_TCP_MD5SIG
	// 这里检查 md5 是否有效，即是否为非 NULL。如果存在 MD5 密钥（即 md5 不为空），则会计算 MD5 签名
	if (md5)
		// 如果启用了 MD5 签名支持，SYN-ACK 包将会通过该 MD5 密钥生成哈希并附加到包中，以增强安全性，确保数据包未被篡改
		// 这里调用 calc_md5_hash 来计算 MD5 哈希，确保 SYN-ACK 包在发送时携带正确的 MD5 签名
		tcp_rsk(req)->af_specific->calc_md5_hash(opts.hash_location,
					       md5, req_to_sk(req), skb);
	// 这是解除 RCU（Read-Copy-Update）锁的操作。由于 MD5 签名的计算可能需要访问共享数据（如请求套接字中的 af_specific），
	// 因此在进入该代码块前，代码会使用 rcu_read_lock() 来保护共享资源
	rcu_read_unlock();
#endif
	// 设置 SYN-ACK 数据包的时间戳。now 是之前通过 tcp_clock_ns() 获取的当前时间戳（单位为纳秒）。
	// 此字段 skb->skb_mstamp_ns 用于记录该数据包的时间戳，通常用于测量延迟、计算 RTT 等。
	skb->skb_mstamp_ns = now;
	// 将一个发送延迟加到 skb（即 SYN-ACK 数据包）上
	tcp_add_tx_delay(skb, tp);

	return skb;
}
EXPORT_SYMBOL(tcp_make_synack);

static void tcp_ca_dst_init(struct sock *sk, const struct dst_entry *dst)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_congestion_ops *ca;
	u32 ca_key = dst_metric(dst, RTAX_CC_ALGO);

	if (ca_key == TCP_CA_UNSPEC)
		return;

	rcu_read_lock();
	ca = tcp_ca_find_key(ca_key);
	if (likely(ca && bpf_try_module_get(ca, ca->owner))) {
		bpf_module_put(icsk->icsk_ca_ops, icsk->icsk_ca_ops->owner);
		icsk->icsk_ca_dst_locked = tcp_ca_dst_locked(dst);
		icsk->icsk_ca_ops = ca;
	}
	rcu_read_unlock();
}

/* Do all connect socket setups that can be done AF independent. */
static void tcp_connect_init(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u8 rcv_wscale;
	u32 rcv_wnd;

	/* We'll fix this up when we get a response from the other end.
	 * See tcp_input.c:tcp_rcv_state_process case TCP_SYN_SENT.
	 */
	tp->tcp_header_len = sizeof(struct tcphdr);
	if (sock_net(sk)->ipv4.sysctl_tcp_timestamps)
		tp->tcp_header_len += TCPOLEN_TSTAMP_ALIGNED;

#ifdef CONFIG_TCP_MD5SIG
	if (tp->af_specific->md5_lookup(sk, sk))
		tp->tcp_header_len += TCPOLEN_MD5SIG_ALIGNED;
#endif

	/* If user gave his TCP_MAXSEG, record it to clamp */
	if (tp->rx_opt.user_mss)
		tp->rx_opt.mss_clamp = tp->rx_opt.user_mss;
	tp->max_window = 0;
	tcp_mtup_init(sk);
	tcp_sync_mss(sk, dst_mtu(dst));

	tcp_ca_dst_init(sk, dst);

	if (!tp->window_clamp)
		tp->window_clamp = dst_metric(dst, RTAX_WINDOW);
	tp->advmss = tcp_mss_clamp(tp, dst_metric_advmss(dst));

	tcp_initialize_rcv_mss(sk);

	/* limit the window selection if the user enforce a smaller rx buffer */
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK &&
	    (tp->window_clamp > tcp_full_space(sk) || tp->window_clamp == 0))
		tp->window_clamp = tcp_full_space(sk);

	rcv_wnd = tcp_rwnd_init_bpf(sk);
	if (rcv_wnd == 0)
		rcv_wnd = dst_metric(dst, RTAX_INITRWND);

	tcp_select_initial_window(sk, tcp_full_space(sk),
				  tp->advmss - (tp->rx_opt.ts_recent_stamp ? tp->tcp_header_len - sizeof(struct tcphdr) : 0),
				  &tp->rcv_wnd,
				  &tp->window_clamp,
				  sock_net(sk)->ipv4.sysctl_tcp_window_scaling,
				  &rcv_wscale,
				  rcv_wnd);

	tp->rx_opt.rcv_wscale = rcv_wscale;
	tp->rcv_ssthresh = tp->rcv_wnd;

	sk->sk_err = 0;
	sock_reset_flag(sk, SOCK_DONE);
	tp->snd_wnd = 0;
	tcp_init_wl(tp, 0);
	tcp_write_queue_purge(sk);
	tp->snd_una = tp->write_seq;
	tp->snd_sml = tp->write_seq;
	tp->snd_up = tp->write_seq;
	WRITE_ONCE(tp->snd_nxt, tp->write_seq);

	if (likely(!tp->repair))
		tp->rcv_nxt = 0;
	else
		tp->rcv_tstamp = tcp_jiffies32;
	tp->rcv_wup = tp->rcv_nxt;
	WRITE_ONCE(tp->copied_seq, tp->rcv_nxt);

	inet_csk(sk)->icsk_rto = tcp_timeout_init(sk);
	inet_csk(sk)->icsk_retransmits = 0;
	tcp_clear_retrans(tp);
}

static void tcp_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	__skb_header_release(skb);
	sk_wmem_queued_add(sk, skb->truesize);
	sk_mem_charge(sk, skb->truesize);
	WRITE_ONCE(tp->write_seq, tcb->end_seq);
	tp->packets_out += tcp_skb_pcount(skb);
}

/* Build and send a SYN with data and (cached) Fast Open cookie. However,
 * queue a data-only packet after the regular SYN, such that regular SYNs
 * are retransmitted on timeouts. Also if the remote SYN-ACK acknowledges
 * only the SYN sequence, the data are retransmitted in the first ACK.
 * If cookie is not cached or other error occurs, falls back to send a
 * regular SYN with Fast Open cookie request option.
 */
 // 这段代码的目标是尝试发送一个 带数据的 SYN 包。如果无法发送带数据的 SYN（比如 Cookie 缓存不可用），
 // 则回退到常规的 SYN 包，并附带 Fast Open Cookie 请求选项。
 // 代码说明了如果发送失败（如 Cookie 不可用或其他错误），将会回退到常规的 SYN 连接请求
 // Fast Open Cookie:在第一次连接时，服务器会生成一个 Fast Open Cookie 并返回给客户端。
 // 这个 Cookie 被保存在客户端（通常是浏览器或应用程序的连接库中），并且 与客户端的 IP 和端口号关联，形成一个缓存。
 // 客户端在之后的 连接请求中可以携带这个 Cookie，而不需要再次进行传统的三次握手中的 SYN 阶段。
 // 服务器验证该 Cookie，若验证成功，就可以直接开始发送数据，而不需要等待三次握手的确认。
 // 参数介绍
 // *sk:一个指向套接字 sock 结构体的指针。sk 代表当前的 TCP 套接字，它包含了关于当前 TCP 连接的各种信息，如连接状态、发送队列、接收队列、TCP 状态机等
 // *syn:一个指向 sk_buff（socket buffer）结构体的指针。
 // 在 tcp_send_syn_data 函数中，syn 是一个已经构造好的 SYN 包（即 TCP 连接建立的初始包），它用于在 TCP Fast Open 场景下发送到远端。
 // 这个 sk_buff 包含了即将发送的 SYN 包的信息，比如目标 IP、端口号等。
static int tcp_send_syn_data(struct sock *sk, struct sk_buff *syn)
{	
	// tp：获取与当前套接字关联的 TCP 控制块（tcp_sock）。
	// fo：获取当前连接的 Fast Open 请求（tcp_fastopen_request），该结构体保存了与 Fast Open 相关的所有信息。
	// space：表示可以用于数据的空间大小。
	// err：用于存储函数调用的返回值。
	// syn_data：指向新分配的带数据的 SYN 包。
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_fastopen_request *fo = tp->fastopen_req;
	int space, err = 0;
	struct sk_buff *syn_data;

	//设置 MSS（最大段大小）：如果没有缓存的 MSS，使用 tp->advmss 来设置接收端的最大段大小。
	tp->rx_opt.mss_clamp = tp->advmss;  /* If MSS is not cached */
	// 调用 tcp_fastopen_cookie_check() 函数检查是否有有效的 Fast Open Cookie，
	// 这个函数会确认是否可以使用已缓存的 Cookie。如果没有有效的 Cookie，或者出现其他问题，则跳转到回退部分。
	if (!tcp_fastopen_cookie_check(sk, &tp->rx_opt.mss_clamp, &fo->cookie))
		goto fallback;


	// 使用tcp_mss_clamp调整 MSS：tcp_mss_clamp() 函数根据路径 MTU 和其他因素调整 MSS
	tp->rx_opt.mss_clamp = tcp_mss_clamp(tp, tp->rx_opt.mss_clamp);

	// 该部分在计算剩余空间
	// space 计算出可以用于数据的最大空间，受到 MTU 和 TCP 选项大小（包括可能的中间设备修改）的限制。
	// fo->size 是请求发送的数据大小
	space = __tcp_mtu_to_mss(sk, inet_csk(sk)->icsk_pmtu_cookie) -
		MAX_TCP_OPTION_SPACE;

	space = min_t(size_t, space, fo->size);

	/* limit to order-0 allocations */
	space = min_t(size_t, space, SKB_MAX_HEAD(MAX_TCP_HEADER));

	// 分配一个新的 sk_buff（网络数据包缓冲区）来存放带数据的 SYN 包。space 是可用的空间。
	syn_data = sk_stream_alloc_skb(sk, space, sk->sk_allocation, false);
	if (!syn_data)
		goto fallback;
	// CHECKSUM_PARTIAL 设置表示部分校验和，后续发送时需要重新计算。
	syn_data->ip_summed = CHECKSUM_PARTIAL;
	// memcpy 将原始 SYN 包的控制块（cb）复制到新的 SYN 数据包中，以保留相关信息。
	memcpy(syn_data->cb, syn->cb, sizeof(syn->cb));
	// 如果 space 大于 0（有数据需要发送），则将数据从 fo->data->msg_iter 复制到 syn_data 中。
	if (space) {
		// copy_from_iter 将数据从用户空间复制到内核中的 sk_buff（syn_data）中
		int copied = copy_from_iter(skb_put(syn_data, space), space,
					    &fo->data->msg_iter);
		// 如果复制失败（copied == 0），则清理并释放分配的内存，并跳转到回退部分。
		if (unlikely(!copied)) {
			tcp_skb_tsorted_anchor_cleanup(syn_data);
			kfree_skb(syn_data);
			goto fallback;
		}
		// 如果复制的数据量少于预期，则修剪数据包，并更新 space
		if (copied != space) {
			skb_trim(syn_data, copied);
			space = copied;
		}
		skb_zcopy_set(syn_data, fo->uarg, NULL);
	}
	// 如果数据已经完全复制到 SYN 数据包中（即 space == fo->size），
	// 则将 fo->data 置为 NULL，表示没有更多数据需要发送。
	if (space == fo->size)
		fo->data = NULL;
	// 更新 fo->copied，记录已复制的字节数
	fo->copied = space;
	// 将 syn_data 加入发送队列 tcp_connect_queue_skb，并启动定时器（tcp_chrono_start），表示连接正在忙于数据传输。
	tcp_connect_queue_skb(sk, syn_data);
	if (syn_data->len)
		tcp_chrono_start(sk, TCP_CHRONO_BUSY);

	// 通过 tcp_transmit_skb() 函数发送 syn_data 数据包。
	err = tcp_transmit_skb(sk, syn_data, 1, sk->sk_allocation);

	// 更新 syn 包的时间戳为 syn_data 包的时间戳，确保时间同步。
	syn->skb_mstamp_ns = syn_data->skb_mstamp_ns;

	/* Now full SYN+DATA was cloned and sent (or not),
	 * remove the SYN from the original skb (syn_data)
	 * we keep in write queue in case of a retransmit, as we
	 * also have the SYN packet (with no data) in the same queue.
	 */
	// 更新序列号
	TCP_SKB_CB(syn_data)->seq++;
	//这行代码设置 syn_data 数据包的 TCP 标志位。
	// tcp_flags 字段用于指定该数据包的 TCP 标志
	// TCPHDR_ACK：表示这是一个 确认包（ACK）。SYN-ACK 包会携带此标志，表示接收到客户端的 SYN 包，并准备好继续连接过程。
	// TCPHDR_PSH：表示数据包携带 推送（PSH）标志。PSH 标志告诉接收方，这个数据包的数据应该立即交给上层应用处理，而不是在缓冲区中等待更多的数据。
	TCP_SKB_CB(syn_data)->tcp_flags = TCPHDR_ACK | TCPHDR_PSH;
	// 如果没有报错
	if (!err) {
		// 这行代码更新 tp->syn_data，表示 是否成功发送数据。
		// fo->copied 存储了已成功发送的数据量（例如，Fast Open 请求的数据）。
		// 如果 fo->copied > 0，则表示客户端成功地在 SYN 包中携带了数据，因此设置 tp->syn_data 为 true（1），表示已经发送了带数据的 SYN 包。
		// 否则为false，表示没有发送
		tp->syn_data = (fo->copied > 0);
		// 将 syn_data（带数据的 SYN 包）插入到 重传队列（Retransmission Queue） 中。
		// sk->tcp_rtx_queue 是一个用于存储待重传的 TCP 数据包的红黑树。
		// 即使数据包已被发送，它仍然可能需要在连接过程中进行重传（例如，如果对方没有收到数据包或者连接超时），因此将其插入重传队列中是必要的。
		tcp_rbtree_insert(&sk->tcp_rtx_queue, syn_data);
		// 调用 NET_INC_STATS 宏来增加 TCP 原始数据包发送统计量（LINUX_MIB_TCPORIGDATASENT）。
		// 该统计量记录了发送的原始 TCP 数据量，用于系统的流量监控和调优
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPORIGDATASENT);
		// 收尾
		goto done;
	}

	// 走到这说明err不为0，存在报错
	// 这行代码将 syn_data（代表带数据的 SYN 包）加入到套接字的写队列（sk_write_queue）中。
	// sk_write_queue 是一个双向链表，存储待发送的网络数据包。
	// 如果数据包没有成功发送，它会被放到这个队列中，以便稍后重新尝试发送。
	__skb_queue_tail(&sk->sk_write_queue, syn_data);
	// 这行代码减少 tp->packets_out 计数器的值，表示当前连接待发送的数据包数量减少。
	// tcp_skb_pcount(syn_data) 计算当前 syn_data 数据包的包计数（例如一个数据包可以包含多个 TCP 段），然后从 packets_out 中减去这个计数
	// 更新当前连接待发送的 TCP 包数。
	tp->packets_out -= tcp_skb_pcount(syn_data);

// 这里是代码的回退标记。在出现错误的情况下，跳转到 fallback 位置，执行备用的处理逻辑。主要是发送一个标准的 SYN 包，而不包括数据。
fallback:
	// 将 Fast Open cookie 的长度重置为 0
	// 在 TFO 过程中，如果出现某些错误（如无法发送数据），客户端可能需要重新发送一个标准的 SYN 包（即不带数据的 SYN 包）。
	// 次时，需要清除之前的 Fast Open cookie 信息，以防止在下次发送时使用过时的 cookie。
	if (fo->cookie.len > 0)
		fo->cookie.len = 0;
	// 如果数据未能发送，代码会尝试通过 tcp_transmit_skb 函数发送 标准的 SYN 包（即不带数据的 SYN 包）。
	// tcp_transmit_skb 函数负责将指定的 sk_buff（此处是 syn）传输到网络上
	err = tcp_transmit_skb(sk, syn, 1, sk->sk_allocation);
	if (err)
		// 如果 tcp_transmit_skb 返回错误（即数据包没有成功发送），则设置 tp->syn_fastopen = 0;。
		// 表示 Fast Open 连接尝试失败，将 syn_fastopen 标志置为 0，表示当前连接不再使用 TCP Fast Open。
		tp->syn_fastopen = 0;
done:
	fo->cookie.len = -1;  /* Exclude Fast Open option for SYN retries */
	return err;
}

/* Build a SYN and send it off. */
// 构建SYN包并发送
// 参数介绍：
// *sk:一个指向 sock 结构体的指针，表示当前的 TCP 套接字.
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	// 调用了 tcp_call_bpf 函数，目的是触发一个与 TCP 连接建立过程相关的 eBPF (BPF) 回调操作
	// 这里它触发一个 TCP 连接的 BPF 回调 BPF_SOCK_OPS_TCP_CONNECT_CB(一个与套接字操作相关的 cgroup BPF 程序)，通常用于网络监控或者流量控制
	// BPF:一个通用的框架，能够在 Linux 内核中执行用户定义的代码。
	tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);

	// 试根据当前路由信息来重建 IP 数据包的头部。
	// 如果该函数返回错误，表示路由不可达或其他网络问题，函数会返回 -EHOSTUNREACH
	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */

	// 这个函数用于初始化与连接相关的各种 TCP 参数和状态。
	// 它会配置 TCP 状态机和一些必要的字段（例如初始序列号等）。
	tcp_connect_init(sk);

	// tp->repair 表示当前连接是否处于“修复模式”。如果是修复模式，
	// 则调用 tcp_finish_connect 完成连接，并直接返回。 
	// 修复模式：一个特定的连接状态，通常用于于测试、调试、恢复或特殊操作
	if (unlikely(tp->repair)) {
		tcp_finish_connect(sk, NULL);
		return 0;
	}

	// sk_stream_alloc_skb 用于为发送数据分配一个 sk_buff（socket buffer）。
	// 该缓冲区会用于存放待发送的数据包。
	// 如果分配失败，则返回 -ENOBUFS，表示内存不足
	buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
	if (unlikely(!buff))
		return -ENOBUFS;

	// tcp_init_nondata_skb 函数初始化一个不含数据的 TCP 数据包，这里是用于发送一个 SYN 包。
	// tp->write_seq++ 设置数据包的序列号并递增。
	tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
	// tcp_mstamp_refresh 刷新时间戳
	tcp_mstamp_refresh(tp);
	// tcp_time_stamp 获取当前时间戳并存储在 retrans_stamp 中，用于后续的重传判断。
	tp->retrans_stamp = tcp_time_stamp(tp);

	tcp_connect_queue_skb(sk, buff);
	// tcp_ecn_send_syn 用于处理显式拥塞通知（ECN），这是 TCP 协议中的一种流量控制机制。
	// ECN（Explicit Congestion Notification）：用于在网络出现拥塞时，以更加高效的方式通知传输端，避免因丢包引发的性能损失。
	// ECN 允许网络中的路由器在发生拥塞时标记数据包，而不是丢弃数据包，从而减少了由于丢包而导致的重传和延迟。
	// 其目的是让端系统（发送端和接收端）能够及时察觉拥塞，并采取措施调整传输速率，避免进一步的拥塞
	tcp_ecn_send_syn(sk, buff);
	// 将 SYN 包添加到 TCP 重传队列（tcp_rtx_queue）中，以便在必要时重传。
	tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);

	// 如果是快速打开连接（TCP Fast Open 即TFO），则调用 tcp_send_syn_data 发送带数据的 SYN 包（对应tcp_v4_connect中的TFO延迟连接，直到发送 SYN 包）。
	// 否则，调用 tcp_transmit_skb 发送纯 SYN 包。
	// tcp_transmit_skb 是 TCP 发送数据的核心函数。
	err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
	      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
	if (err == -ECONNREFUSED)
		return err;

	// WRITE_ONCE 是一个保证写入操作只执行一次的宏，
	// 确保更新发送序列号 snd_nxt，并且设置 pushed_seq 为当前的写序列号。
	WRITE_ONCE(tp->snd_nxt, tp->write_seq);
	tp->pushed_seq = tp->write_seq;
	// tcp_send_head() 函数用于返回当前 TCP 连接的待发送报文段（sk_buff）。
	// sk_buff 是 Linux 内核中用来表示一个网络数据包的结构。
	// 该函数的具体功能是获取当前 TCP 连接中最前面的待发送数据包，也就是下一个要发送的数据包
	buff = tcp_send_head(sk);
	// 是一个条件宏，表示我们期望 buff 很少为 NULL（即我们期望大多数情况下都有待发送的报文段）。
	// 这个宏是基于编译器的优化，告诉编译器这个分支的条件不太可能成立，从而优化 CPU 缓存的使用，提高代码效率。
	if (unlikely(buff)) {
		// 更新 TCP 连接的发送序列号 snd_nxt 为当前待发送报文段的序列号。
		WRITE_ONCE(tp->snd_nxt, TCP_SKB_CB(buff)->seq);
		//将当前待发送报文段的序列号赋给 pushed_seq，表示已经“推进”到这个序列号的报文段。
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	// 更新 TCP 连接统计信息，增加 ACTIVEOPENS 计数，表示一个新的连接请求。
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	// 设置一个重传定时器，icsk_rto 是当前重传超时（RTO）值。
	// 如果发送的 SYN 包未得到响应，则在超时后进行重传。
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
EXPORT_SYMBOL(tcp_connect);

/* Send out a delayed ack, the caller does the policy checking
 * to see if we should even be here.  See tcp_input.c:tcp_ack_snd_check()
 * for details.
 */
void tcp_send_delayed_ack(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int ato = icsk->icsk_ack.ato;
	unsigned long timeout;

	if (ato > TCP_DELACK_MIN) {
		const struct tcp_sock *tp = tcp_sk(sk);
		int max_ato = HZ / 2;

		if (inet_csk_in_pingpong_mode(sk) ||
		    (icsk->icsk_ack.pending & ICSK_ACK_PUSHED))
			max_ato = TCP_DELACK_MAX;

		/* Slow path, intersegment interval is "high". */

		/* If some rtt estimate is known, use it to bound delayed ack.
		 * Do not use inet_csk(sk)->icsk_rto here, use results of rtt measurements
		 * directly.
		 */
		if (tp->srtt_us) {
			int rtt = max_t(int, usecs_to_jiffies(tp->srtt_us >> 3),
					TCP_DELACK_MIN);

			if (rtt < max_ato)
				max_ato = rtt;
		}

		ato = min(ato, max_ato);
	}

	/* Stay within the limit we were given */
	timeout = jiffies + ato;

	/* Use new timeout only if there wasn't a older one earlier. */
	if (icsk->icsk_ack.pending & ICSK_ACK_TIMER) {
		/* If delack timer was blocked or is about to expire,
		 * send ACK now.
		 */
		if (icsk->icsk_ack.blocked ||
		    time_before_eq(icsk->icsk_ack.timeout, jiffies + (ato >> 2))) {
			tcp_send_ack(sk);
			return;
		}

		if (!time_before(timeout, icsk->icsk_ack.timeout))
			timeout = icsk->icsk_ack.timeout;
	}
	icsk->icsk_ack.pending |= ICSK_ACK_SCHED | ICSK_ACK_TIMER;
	icsk->icsk_ack.timeout = timeout;
	sk_reset_timer(sk, &icsk->icsk_delack_timer, timeout);
}

// 送一个 TCP ACK 包（确认包），并且更新接收窗口
// 参数介绍：
// sk：指向当前套接字（struct sock）的指针，表示当前的 TCP 连接。
// rcv_nxt：是接收窗口中的下一个期望的序列号，用于确定发送的 ACK 包的序列号。
void __tcp_send_ack(struct sock *sk, u32 rcv_nxt)
{
	struct sk_buff *buff;

	// 检查套接字的状态是否为 TCP_CLOSE。如果是，表示连接已经关闭，不能再发送任何数据或 ACK，因此直接返回。
	if (sk->sk_state == TCP_CLOSE)
		return;

	// lloc_skb：分配一个新的 sk_buff（socket buffer），它用于承载网络数据包。这里使用 MAX_TCP_HEADER 来确定分配的空间大小，这个值表示 TCP 头的最大大小。
	// sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN)：用于指定分配内存的标志，GFP_ATOMIC 表示以原子方式分配内存，__GFP_NOWARN 防止在内存分配失败时输出警告。
	buff = alloc_skb(MAX_TCP_HEADER,
			 sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	// 如果分配 skb 失败（buff 为 NULL），则需要进行一些回退操作。
	// inet_csk_schedule_ack(sk)：调度一个延迟 ACK。
	// inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN：设置 ACK 的超时为最小值。
	// inet_csk_reset_xmit_timer：重置重传计时器，并设定超时时间，ICSK_TIME_DACK 表示延迟 ACK 的定时器。
	if (unlikely(!buff)) {
		inet_csk_schedule_ack(sk);
		inet_csk(sk)->icsk_ack.ato = TCP_ATO_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK,
					  TCP_DELACK_MAX, TCP_RTO_MAX);
		return;
	}

	// kb_reserve(buff, MAX_TCP_HEADER)：为数据包保留空间以存放 TCP 头部。
	skb_reserve(buff, MAX_TCP_HEADER);
	// tcp_init_nondata_skb：初始化 skb，并设置适当的 TCP 序列号和控制标志（此处为 TCPHDR_ACK，即 ACK 标志）。
	// 使用tcp_acceptable_seq(sk) 获取当前可接受的序列号。
	tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);

	// 设置 skb 为纯 ACK 包。纯 ACK 包是指不携带数据的 ACK 包，它用于确认接收到的数据，而不携带任何有效负载。
	// 以是避免纯 ACK 包对 TCP 小队列或流量控制（fq/pacing）产生过多影响
	skb_set_tcp_pure_ack(buff);

	// 将构建好的 skb 发送出去。rcv_nxt 是接收方期望接收的下一个序列号，用于更新接收窗口。
	// 这个函数会处理数据包的传输，并根据需要更新延迟 ACK 的相关状态
	// 该函数已经在前面讲解过
	__tcp_transmit_skb(sk, buff, 0, (__force gfp_t)0, rcv_nxt);
}
// 将 __tcp_send_ack 函数导出，使其可以被其他模块访问
EXPORT_SYMBOL_GPL(__tcp_send_ack);

void tcp_send_ack(struct sock *sk)
{
	__tcp_send_ack(sk, tcp_sk(sk)->rcv_nxt);
}

/* This routine sends a packet with an out of date sequence
 * number. It assumes the other end will try to ack it.
 *
 * Question: what should we make while urgent mode?
 * 4.4BSD forces sending single byte of data. We cannot send
 * out of window data, because we have SND.NXT==SND.MAX...
 *
 * Current solution: to send TWO zero-length segments in urgent mode:
 * one is with SEG.SEQ=SND.UNA to deliver urgent pointer, another is
 * out-of-date with SND.UNA-1 to probe window.
 */
static int tcp_xmit_probe_skb(struct sock *sk, int urgent, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	/* We don't queue it, tcp_transmit_skb() sets ownership. */
	skb = alloc_skb(MAX_TCP_HEADER,
			sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));
	if (!skb)
		return -1;

	/* Reserve space for headers and set control bits. */
	skb_reserve(skb, MAX_TCP_HEADER);
	/* Use a previous sequence.  This should cause the other
	 * end to send an ack.  Don't queue or clone SKB, just
	 * send it.
	 */
	tcp_init_nondata_skb(skb, tp->snd_una - !urgent, TCPHDR_ACK);
	NET_INC_STATS(sock_net(sk), mib);
	return tcp_transmit_skb(sk, skb, 0, (__force gfp_t)0);
}

/* Called from setsockopt( ... TCP_REPAIR ) */
void tcp_send_window_probe(struct sock *sk)
{
	if (sk->sk_state == TCP_ESTABLISHED) {
		tcp_sk(sk)->snd_wl1 = tcp_sk(sk)->rcv_nxt - 1;
		tcp_mstamp_refresh(tcp_sk(sk));
		tcp_xmit_probe_skb(sk, 0, LINUX_MIB_TCPWINPROBE);
	}
}

/* Initiate keepalive or window probe from timer. */
int tcp_write_wakeup(struct sock *sk, int mib)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb;

	if (sk->sk_state == TCP_CLOSE)
		return -1;

	skb = tcp_send_head(sk);
	if (skb && before(TCP_SKB_CB(skb)->seq, tcp_wnd_end(tp))) {
		int err;
		unsigned int mss = tcp_current_mss(sk);
		unsigned int seg_size = tcp_wnd_end(tp) - TCP_SKB_CB(skb)->seq;

		if (before(tp->pushed_seq, TCP_SKB_CB(skb)->end_seq))
			tp->pushed_seq = TCP_SKB_CB(skb)->end_seq;

		/* We are probing the opening of a window
		 * but the window size is != 0
		 * must have been a result SWS avoidance ( sender )
		 */
		if (seg_size < TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq ||
		    skb->len > mss) {
			seg_size = min(seg_size, mss);
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
			if (tcp_fragment(sk, TCP_FRAG_IN_WRITE_QUEUE,
					 skb, seg_size, mss, GFP_ATOMIC))
				return -1;
		} else if (!tcp_skb_pcount(skb))
			tcp_set_skb_tso_segs(skb, mss);

		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_PSH;
		err = tcp_transmit_skb(sk, skb, 1, GFP_ATOMIC);
		if (!err)
			tcp_event_new_data_sent(sk, skb);
		return err;
	} else {
		if (between(tp->snd_up, tp->snd_una + 1, tp->snd_una + 0xFFFF))
			tcp_xmit_probe_skb(sk, 1, mib);
		return tcp_xmit_probe_skb(sk, 0, mib);
	}
}

/* A window probe timeout has occurred.  If window is not closed send
 * a partial packet else a zero probe.
 */
void tcp_send_probe0(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct net *net = sock_net(sk);
	unsigned long timeout;
	int err;

	err = tcp_write_wakeup(sk, LINUX_MIB_TCPWINPROBE);

	if (tp->packets_out || tcp_write_queue_empty(sk)) {
		/* Cancel probe timer, if it is not required. */
		icsk->icsk_probes_out = 0;
		icsk->icsk_backoff = 0;
		return;
	}

	icsk->icsk_probes_out++;
	if (err <= 0) {
		if (icsk->icsk_backoff < net->ipv4.sysctl_tcp_retries2)
			icsk->icsk_backoff++;
		timeout = tcp_probe0_when(sk, TCP_RTO_MAX);
	} else {
		/* If packet was not sent due to local congestion,
		 * Let senders fight for local resources conservatively.
		 */
		timeout = TCP_RESOURCE_PROBE_INTERVAL;
	}
	tcp_reset_xmit_timer(sk, ICSK_TIME_PROBE0, timeout, TCP_RTO_MAX, NULL);
}

int tcp_rtx_synack(const struct sock *sk, struct request_sock *req)
{
	const struct tcp_request_sock_ops *af_ops = tcp_rsk(req)->af_specific;
	struct flowi fl;
	int res;

	tcp_rsk(req)->txhash = net_tx_rndhash();
	res = af_ops->send_synack(sk, NULL, &fl, req, NULL, TCP_SYNACK_NORMAL);
	if (!res) {
		__TCP_INC_STATS(sock_net(sk), TCP_MIB_RETRANSSEGS);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNRETRANS);
		if (unlikely(tcp_passive_fastopen(sk)))
			tcp_sk(sk)->total_retrans++;
		trace_tcp_retransmit_synack(sk, req);
	}
	return res;
}
EXPORT_SYMBOL(tcp_rtx_synack);
