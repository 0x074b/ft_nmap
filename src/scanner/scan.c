#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/ip_icmp.h>
#include <linux/if_packet.h>

#include "scanner_internal.h"

/*
** Dispatch table: one entry per t_scan_type. SYN and ACK carry real probe
** builders and reply classifiers; FIN, NULL, XMAS and UDP are placeholders
** (their send/recv are stubs) but are still wired in so the whole program
** runs — and reports — uniformly across every scan type.
*/
static const t_scan_ops	g_scan_ops[SCAN_MAX] = {
	[SCAN_SYN] = {syn_send, syn_recv, PORT_FILTERED, "SYN"},
	[SCAN_ACK] = {ack_send, ack_recv, PORT_FILTERED, "ACK"},
	[SCAN_FIN] = {fin_send, fin_recv, PORT_OPEN_FILTERED, "FIN"},
	[SCAN_NULL] = {null_send, null_recv, PORT_OPEN_FILTERED, "NULL"},
	[SCAN_XMAS] = {xmas_send, xmas_recv, PORT_OPEN_FILTERED, "XMAS"},
	[SCAN_UDP] = {udp_send, udp_recv, PORT_OPEN_FILTERED, "UDP"},
};

const t_scan_ops	*scan_ops(t_scan_type type)
{
	if (type < 0 || type >= SCAN_MAX)
		return (NULL);
	return (&g_scan_ops[type]);
}

/*
** Split an IP packet into 8-byte payload fragments and send each in order.
** Fragment 1 carries the first 8 bytes of the transport header with MF=1;
** fragment 2 carries the rest with offset=1 (8 bytes). Both recompute the
** IP checksum over their own header. Returns -1 if either sendto fails.
*/
static int	send_fragmented(const t_sender *s, const uint8_t *buf, size_t len,
		struct in_addr dst, uint16_t dport)
{
	const struct iphdr	*orig;
	struct iphdr		*iph1;
	struct iphdr		*iph2;
	uint8_t				frag1[20 + 8];
	uint8_t				frag2[MAX_PROBE_LEN];
	struct sockaddr_in	to;
	size_t				ip_hlen;
	size_t				payload_len;
	size_t				frag1_plen;
	size_t				frag2_plen;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	to.sin_port = htons(dport);
	orig = (const struct iphdr *)buf;
	ip_hlen = (size_t)orig->ihl * 4;
	if (len <= ip_hlen)
		return (sendto(s->sock, buf, len, 0,
			(struct sockaddr *)&to, sizeof(to)) < 0 ? -1 : 0);
	payload_len = len - ip_hlen;
	frag1_plen = payload_len >= 8 ? 8 : payload_len;
	frag2_plen = payload_len - frag1_plen;
	/* Fragment 1: IP header + first frag1_plen bytes, MF=1, offset=0 */
	memcpy(frag1, buf, ip_hlen + frag1_plen);
	iph1 = (struct iphdr *)frag1;
	iph1->tot_len = htons((uint16_t)(ip_hlen + frag1_plen));
	iph1->frag_off = htons(IP_MF);
	iph1->check = 0;
	iph1->check = ip_checksum(iph1, ip_hlen);
	if (sendto(s->sock, frag1, ip_hlen + frag1_plen, 0,
		(struct sockaddr *)&to, sizeof(to)) < 0)
		return (-1);
	if (frag2_plen == 0)
		return (0);
	/* Fragment 2: IP header + remaining bytes, MF=0, offset=frag1_plen/8 */
	memcpy(frag2, buf, ip_hlen);
	memcpy(frag2 + ip_hlen, buf + ip_hlen + frag1_plen, frag2_plen);
	iph2 = (struct iphdr *)frag2;
	iph2->tot_len = htons((uint16_t)(ip_hlen + frag2_plen));
	iph2->frag_off = htons((uint16_t)(frag1_plen / 8));
	iph2->check = 0;
	iph2->check = ip_checksum(iph2, ip_hlen);
	if (sendto(s->sock, frag2, ip_hlen + frag2_plen, 0,
		(struct sockaddr *)&to, sizeof(to)) < 0)
		return (-1);
	return (0);
}

/*
** Send a packet via an AF_PACKET (L2) socket with the fake source MAC set
** in the Ethernet header. Uses sendmsg + iovec to avoid an extra copy.
*/
static int	send_l2(const t_sender *s, const uint8_t *buf, size_t len)
{
	uint8_t				eth_hdr[14];
	struct iovec		iov[2];
	struct msghdr		msg;
	struct sockaddr_ll	ll;

	memcpy(eth_hdr, s->gw_mac, 6);
	memcpy(eth_hdr + 6, s->opts->fake_mac, 6);
	eth_hdr[12] = 0x08;
	eth_hdr[13] = 0x00;
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = s->ifindex;
	ll.sll_halen = 6;
	memcpy(ll.sll_addr, s->gw_mac, 6);
	iov[0].iov_base = eth_hdr;
	iov[0].iov_len = 14;
	iov[1].iov_base = (void *)buf;
	iov[1].iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &ll;
	msg.msg_namelen = sizeof(ll);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	return (sendmsg(s->l2_sock, &msg, 0) < 0 ? -1 : 0);
}

int	scan_send_raw(const t_sender *s, const uint8_t *buf, size_t len,
		struct in_addr dst, uint16_t dport)
{
	struct sockaddr_in	to;

	if (s->l2_sock >= 0)
		return (send_l2(s, buf, len));
	if (s->opts && s->opts->fragment)
		return (send_fragmented(s, buf, len, dst, dport));
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	to.sin_port = htons(dport);
	if (sendto(s->sock, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
		return (-1);
	return (0);
}

static uint64_t	now_ms(void)
{
	struct timeval	tv;

	gettimeofday(&tv, NULL);
	return ((uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

/*
** Map the libpcap datalink type to the link-layer header size we need to
** skip before reaching the IP header.
*/
static size_t	dl_header_size(int dl)
{
	if (dl == DLT_EN10MB)
		return (14);
	if (dl == DLT_NULL)
		return (4);
	if (dl == DLT_LINUX_SLL)
		return (16);
	if (dl == DLT_RAW)
		return (0);
	return (14);
}

/*
** Map a reply's source IPv4 (in network byte order) back to the index of
** the host that was probed. Linear scan is fine — ip_count <= MAX_TARGETS.
** Returns -1 if no host matches (stray packet, filter let it slip, etc.).
*/
static int	find_host_idx(const t_options *opts, uint32_t saddr)
{
	size_t	h;

	h = 0;
	while (h < opts->ip_count)
	{
		if (opts->ips[h].addr.s_addr == saddr)
			return ((int)h);
		h++;
	}
	return (-1);
}

/*
** Map a reply's destination port (one of our source ports) back to the scan
** type it belongs to. Because every selected scan type uses its own sport,
** this is how we tell, e.g., a SYN-scan RST apart from an ACK-scan RST.
** Returns -1 for ports we did not send from.
*/
static int	type_for_sport(const t_options *opts, const uint16_t *sports,
		uint16_t dport)
{
	int	t;

	t = 0;
	while (t < SCAN_MAX)
	{
		if (opts->scan[t] && sports[t] == dport)
			return (t);
		t++;
	}
	return (-1);
}

/*
** Demultiplex one captured reply into the results table: saddr -> host,
** dest port -> scan type, source port -> target port, then that type's
** classifier turns the flags into a port state. PORT_UNKNOWN means "no
** verdict" so the slot keeps the no_reply_state prefill_results pre-filled.
** Called only from the single receiver thread, so the writes need no lock.
*/
static void	handle_reply(const t_receiver *r, size_t off,
		const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct iphdr	*iph;
	const struct tcphdr	*tcph;
	const struct udphdr	*udph;
	const struct icmphdr	*icmph;
	const struct iphdr	*inner_iph;
	const struct udphdr	*inner_udph;
	t_port_state		s;
	int				h;
	int				t;
	uint16_t		port;
	size_t			iph_len;

	if (hdr->caplen < off + sizeof(*iph))
		return ;
	iph = (const struct iphdr *)(data + off);
	h = find_host_idx(r->opts, iph->saddr);
	if (h < 0)
		return ;
	iph_len = iph->ihl * 4;
	if (iph->protocol == IPPROTO_TCP)
	{
		if (hdr->caplen < off + iph_len + sizeof(*tcph))
			return ;
		tcph = (const struct tcphdr *)((const uint8_t *)iph + iph_len);
		t = type_for_sport(r->opts, r->sports, ntohs(tcph->dest));
		if (t < 0)
			return ;
		port = ntohs(tcph->source);
		if (port > MAX_PORTS || !r->opts->ports[port])
			return ;
		s = scan_ops(t)->classify(tcph);
		if (s != PORT_UNKNOWN)
			r->results[h][port].state[t] = s;

		/* OS Detection: Extract fingerprint from SYN-ACK or RST */
		if (r->opts->os_detection && ((tcph->syn && tcph->ack) || tcph->rst))
			os_extract_fingerprint(h, (struct iphdr *)iph, (struct tcphdr *)tcph);

		return ;
	}
	if (iph->protocol == IPPROTO_UDP)
	{
		if (hdr->caplen < off + iph_len + sizeof(*udph))
			return ;
		udph = (const struct udphdr *)((const uint8_t *)iph + iph_len);
		t = type_for_sport(r->opts, r->sports, ntohs(udph->dest));
		if (t != SCAN_UDP)
			return ;
		port = ntohs(udph->source);
		if (port > MAX_PORTS || !r->opts->ports[port])
			return ;
		r->results[h][port].state[t] = PORT_OPEN;
		return ;
	}
	if (iph->protocol == IPPROTO_ICMP)
	{
		if (hdr->caplen < off + iph_len + sizeof(*icmph))
			return ;
		icmph = (const struct icmphdr *)((const uint8_t *)iph + iph_len);
		if (icmph->type != ICMP_DEST_UNREACH)
			return ;
		if (hdr->caplen < off + iph_len + sizeof(*icmph) + sizeof(*inner_iph))
			return ;
		inner_iph = (const struct iphdr *)((const uint8_t *)icmph + sizeof(*icmph));
		if (inner_iph->protocol != IPPROTO_UDP)
			return ;
		inner_udph = (const struct udphdr *)((const uint8_t *)inner_iph + inner_iph->ihl * 4);
		t = type_for_sport(r->opts, r->sports, ntohs(inner_udph->source));
		if (t != SCAN_UDP)
			return ;
		port = ntohs(inner_udph->dest);
		if (port > MAX_PORTS || !r->opts->ports[port])
			return ;
		if (icmph->code == ICMP_PORT_UNREACH)
			s = PORT_CLOSED;
		else
			s = PORT_FILTERED;
		r->results[h][port].state[t] = s;
	}
}

/*
** Drain every reply currently buffered on the handle, demuxing each through
** handle_reply. Returns the terminating pcap_next_ex code: 0 once the ring is
** empty, <0 on error.
*/
static int	drain_ready(t_receiver *r, size_t off)
{
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	int					rc;

	while ((rc = pcap_next_ex(r->p, &hdr, &data)) > 0)
		handle_reply(r, off, hdr, data);
	return (rc);
}

/*
** Receiver thread: the sole reader of the one shared capture handle and the
** sole writer of results. It sleeps in poll() on the handle's selectable fd and
** drains every ready reply, so a single core kept fed with packets never lets
** the ring back up (the old per-worker rings starved and dropped). It runs
** until the senders signal they are done, then keeps draining for
** COLLECT_GRACE_MS more to catch RTT-delayed stragglers. Falls back to a plain
** spin if the handle exposes no selectable fd.
*/
void	*receiver_main(void *arg)
{
	t_receiver		*r;
	struct pollfd	pfd;
	size_t			off;
	uint64_t		grace_deadline;
	int				fd;

	r = (t_receiver *)arg;
	off = dl_header_size(pcap_datalink(r->p));
	fd = pcap_get_selectable_fd(r->p);
	pfd.fd = fd;
	pfd.events = POLLIN;
	grace_deadline = 0;
	while (1)
	{
		if (fd >= 0)
			poll(&pfd, 1, 100);
		if (drain_ready(r, off) < 0)
			break ;
		if (*r->senders_done)
		{
			if (grace_deadline == 0)
				grace_deadline = now_ms() + COLLECT_GRACE_MS;
			else if (now_ms() >= grace_deadline)
				break ;
		}
	}
	drain_ready(r, off);
	return (NULL);
}

/*
** Stamp every selected scan type's no_reply_state into each active (host, port)
** slot. Done single-threaded before any sender starts, so once probes fly the
** receiver is the only thread writing results — no lock needed. A slot the
** receiver never updates keeps this default (the "no answer" verdict).
*/
void	prefill_results(const t_options *opts, t_scan_result **results,
		const uint16_t *active_ports, int nports)
{
	size_t	h;
	int		pi;
	int		t;

	h = 0;
	while (h < opts->ip_count)
	{
		pi = 0;
		while (pi < nports)
		{
			t = 0;
			while (t < SCAN_MAX)
			{
				if (opts->scan[t])
					results[h][active_ports[pi]].state[t]
						= scan_ops(t)->no_reply_state;
				t++;
			}
			pi++;
		}
		h++;
	}
}

/*
** Emit every probe this sender owns for one (host, port) pair: one probe per
** selected scan type, each from that type's shared source port. Replies are
** captured and recorded by the receiver thread, not here. *sent counts probes
** for optional pacing.
*/
static void	send_host_port_probes(t_sender *s, size_t h, int port,
		size_t *sent)
{
	const t_scan_ops	*ops;
	t_sender			decoy_s;
	struct in_addr		dst;
	int					t;
	int					d;

	dst = s->opts->ips[h].addr;
	t = 0;
	while (t < SCAN_MAX)
	{
		if (s->opts->scan[t])
		{
			ops = scan_ops(t);
			/* Send from each decoy IP before the real probe */
			d = 0;
			while (d < s->opts->decoy_count)
			{
				decoy_s = *s;
				decoy_s.src = s->opts->decoys[d].ip;
				ops->send(&decoy_s, s->sports[t], dst, (uint16_t)port);
				d++;
			}
			/* Send the real probe */
			if (ops->send(s, s->sports[t], dst, (uint16_t)port) < 0)
				s->send_fail++;
			/* Optional delay between probes (--scan-delay) */
			if (s->opts->scan_delay_ms > 0)
				usleep(s->opts->scan_delay_ms * 1000);
#if PROBE_PACING_US > 0
			if (++(*sent) % PROBE_PACING_BATCH == 0)
				usleep(PROBE_PACING_US);
#else
			(void)sent;
#endif
		}
		t++;
	}
}

/*
** Sender thread entry point. Work is the flattened host * port space: unit u
** maps to host u / nports and port active_ports[u % nports], and this sender
** owns every unit u where u % nsenders == id. Striding the *combined* space
** keeps every sender busy whether the scan is a few hosts on many ports or many
** hosts on a few ports. Senders only transmit; the receiver thread drains the
** shared handle. Returns NULL to satisfy the pthread start-routine signature.
*/
void	*sender_main(void *arg)
{
	t_sender	*s;
	size_t		sent;
	size_t		total;
	size_t		u;

	s = (t_sender *)arg;
	sent = 0;
	total = s->opts->ip_count * (size_t)s->nports;
	u = (size_t)s->id;
	while (u < total)
	{
		send_host_port_probes(s, u / (size_t)s->nports,
			s->active_ports[u % (size_t)s->nports], &sent);
		u += (size_t)s->nsenders;
	}
	return (NULL);
}
