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
static int	type_for_sport(const t_worker *w, uint16_t dport)
{
	int	t;

	t = 0;
	while (t < SCAN_MAX)
	{
		if (w->opts->scan[t] && w->sport[t] == dport)
			return (t);
		t++;
	}
	return (-1);
}

/*
** Demultiplex one captured TCP reply into the results table: saddr -> host,
** dest port -> scan type, source port -> target port, then that type's
** classifier turns the flags into a port state. PORT_UNKNOWN means "no
** verdict" so the slot keeps the no_reply_state scan_run pre-filled.
*/
static void	handle_reply(const t_worker *w, size_t off,
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
	h = find_host_idx(w->opts, iph->saddr);
	if (h < 0)
		return ;
	iph_len = iph->ihl * 4;
	if (iph->protocol == IPPROTO_TCP)
	{
		if (hdr->caplen < off + iph_len + sizeof(*tcph))
			return ;
		tcph = (const struct tcphdr *)((const uint8_t *)iph + iph_len);
		t = type_for_sport(w, ntohs(tcph->dest));
		if (t < 0)
			return ;
		port = ntohs(tcph->source);
		if (port > MAX_PORTS || !w->opts->ports[port])
			return ;
		s = scan_ops(t)->classify(tcph);
		if (s != PORT_UNKNOWN)
			w->results[h][port].state[t] = s;
		
		/* OS Detection: Extract fingerprint from SYN-ACK or RST */
		if (w->opts->os_detection && ((tcph->syn && tcph->ack) || tcph->rst))
			os_extract_fingerprint(h, (struct iphdr *)iph, (struct tcphdr *)tcph);
		
		return ;
	}
	if (iph->protocol == IPPROTO_UDP)
	{
		if (hdr->caplen < off + iph_len + sizeof(*udph))
			return ;
		udph = (const struct udphdr *)((const uint8_t *)iph + iph_len);
		t = type_for_sport(w, ntohs(udph->dest));
		if (t != SCAN_UDP)
			return ;
		port = ntohs(udph->source);
		if (port > MAX_PORTS || !w->opts->ports[port])
			return ;
		w->results[h][port].state[t] = PORT_OPEN;
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
		t = type_for_sport(w, ntohs(inner_udph->source));
		if (t != SCAN_UDP)
			return ;
		port = ntohs(inner_udph->dest);
		if (port > MAX_PORTS || !w->opts->ports[port])
			return ;
		if (icmph->code == ICMP_PORT_UNREACH)
			s = PORT_CLOSED;
		else
			s = PORT_FILTERED;
		w->results[h][port].state[t] = s;
	}
}

/*
** Drain every reply currently buffered on the handle, demuxing each through
** handle_reply. Returns the terminating pcap_next_ex code: 0 once the ring is
** empty, <0 on error.
*/
static int	drain_ready(t_worker *w, size_t off)
{
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	int					rc;
	int					count;

	count = 0;
	while ((rc = pcap_next_ex(w->p, &hdr, &data)) > 0)
	{
		handle_reply(w, off, hdr, data);
		count++;
	}
	if (rc < 0)
		return (-1);
	return (count);
}

/*
** Final collection window: wait for stragglers after all probes have been
** sent.
**
** Two-stage design:
**   1. Before the first reply arrives (received_any == 0) the idle cutoff is
**      suppressed entirely.  We just poll() in IDLE_CUTOFF_MS slices so the
**      loop stays responsive without spinning.  This guarantees we always
**      wait at least one full RTT even on fast (SYN-only) scans where all
**      probes are sent before the first reply arrives.
**   2. Once the first reply lands (received_any == 1) we start the idle timer.
**      If no new packet arrives within IDLE_CUTOFF_MS we declare the burst
**      finished and exit — this keeps local scans fast.
**
** HARD_DEADLINE_MS is a safety net: we never wait longer than this regardless
** of reply activity (guards against a trickle of replies from a slow target).
**
** IDLE_CUTOFF_MS = 150ms instead of the old 50ms so that the burst window
** outlasts the probe-send phase for high-numbered ports on ~67ms-RTT hosts
** (last probe at ~290ms, reply at ~357ms — 50ms was too short).
*/
# define HARD_DEADLINE_MS	1000
# define IDLE_CUTOFF_MS		150

static void	scan_collect_replies(t_worker *w, size_t off)
{
	struct pollfd	pfd;
	uint64_t		deadline;
	uint64_t		idle_since;
	int				fd;
	int				got;
	int				received_any;

	fd = pcap_get_selectable_fd(w->p);
	pfd.fd = fd;
	pfd.events = POLLIN;
	deadline = now_ms() + HARD_DEADLINE_MS;
	idle_since = now_ms();
	received_any = 0;
	while (now_ms() < deadline)
	{
		if (received_any && (now_ms() - idle_since >= IDLE_CUTOFF_MS))
			break ;
		if (fd >= 0 && poll(&pfd, 1, IDLE_CUTOFF_MS) <= 0)
			continue ;
		got = drain_ready(w, off);
		if (got < 0)
			break ;
		if (got > 0)
		{
			idle_since = now_ms();
			received_any = 1;
		}
	}
}

/*
** Send every probe this worker owns for one target port: for each selected
** scan type, mark the slot with that type's no_reply_state and emit the probe
** (from that type's source port) to every host. *sent tracks probes emitted
** since the last flush; once it crosses PROBE_FLUSH_THRESHOLD the capture
** buffer is drained mid-burst and the counter reset. The check lives in the
** innermost loop so even a single port with a huge host list cannot outrun
** the kernel buffer.
*/
static void	send_port_probes(t_worker *w, int port, size_t off, size_t *sent)
{
	const t_scan_ops	*ops;
	size_t				h;
	int					t;

	t = 0;
	while (t < SCAN_MAX)
	{
		if (w->opts->scan[t])
		{
			ops = scan_ops(t);
			for (h = 0; h < w->opts->ip_count; h++)
			{
				w->results[h][port].state[t] = ops->no_reply_state;
				if (ops->send(w->sock, w->src, w->sport[t],
						w->opts->ips[h].addr, (uint16_t)port) < 0)
					w->send_fail++;
				if (++(*sent) >= PROBE_FLUSH_THRESHOLD)
				{
					drain_ready(w, off);
					*sent = 0;
				}
			}
		}
		t++;
	}
}

/*
** One worker's full pass. It owns every port p where (p - 1) % nthreads == id.
** It fires probes across its whole stride, draining the capture buffer every
** PROBE_FLUSH_THRESHOLD sends (handled inside send_port_probes) so no host-list
** size can overflow the kernel buffer. A final collection window then catches
** stragglers still in flight after the last batch.
*/
void	scan_run(t_worker *w)
{
	size_t	off;
	size_t	sent;
	int		port;

	off = dl_header_size(pcap_datalink(w->p));
	sent = 0;
	port = w->id + 1;
	while (port <= MAX_PORTS)
	{
		if (w->opts->ports[port])
			send_port_probes(w, port, off, &sent);
		port += w->nthreads;
	}
	scan_collect_replies(w, off);
}
