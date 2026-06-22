#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
** Final collection window draining this worker's pcap handle for 1000ms,
** giving late (RTT-delayed) replies time to arrive. The BPF filter already
** narrows to replies destined to any of our source ports, so handle_reply
** does the per-packet demultiplexing.
*/
static void	scan_collect_replies(t_worker *w, size_t off)
{
	uint64_t			deadline;
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	int					rc;

	deadline = now_ms() + 1000;
	while (now_ms() < deadline)
	{
		rc = pcap_next_ex(w->p, &hdr, &data);
		if (rc == 0)
		{
			usleep(1000);
			continue ;
		}
		if (rc < 0)
			break ;
		handle_reply(w, off, hdr, data);
	}
}

/*
** Mid-scan flush: drain every reply currently buffered, then return at once.
** The handle is non-blocking, so pcap_next_ex returning 0 means the buffer is
** empty. Called between send batches to keep the kernel capture buffer from
** overflowing without paying the full collection window each time — stragglers
** still in flight are caught by the next flush or the final window.
*/
static void	scan_drain(t_worker *w, size_t off)
{
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	int					rc;

	while (1)
	{
		rc = pcap_next_ex(w->p, &hdr, &data);
		if (rc <= 0)
			break ;
		handle_reply(w, off, hdr, data);
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
				ops->send(w->sock, w->src, w->sport[t],
					w->opts->ips[h].addr, (uint16_t)port);
				if (++(*sent) >= PROBE_FLUSH_THRESHOLD)
				{
					scan_drain(w, off);
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
