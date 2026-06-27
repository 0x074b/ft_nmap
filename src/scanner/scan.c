#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>

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

int	scan_send_raw(int sock, const uint8_t *buf, size_t len,
		struct in_addr dst, uint16_t dport)
{
	struct sockaddr_in	to;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	to.sin_port = htons(dport);
	if (sendto(sock, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
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
	int					t;

	t = 0;
	while (t < SCAN_MAX)
	{
		if (s->opts->scan[t])
		{
			ops = scan_ops(t);
			if (ops->send(s->sock, s->src, s->sports[t],
					s->opts->ips[h].addr, (uint16_t)port) < 0)
				s->send_fail++;
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
