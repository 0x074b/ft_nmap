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
	[SCAN_FIN] = {fin_send, fin_recv, PORT_UNKNOWN, "FIN"},
	[SCAN_NULL] = {null_send, null_recv, PORT_UNKNOWN, "NULL"},
	[SCAN_XMAS] = {xmas_send, xmas_recv, PORT_UNKNOWN, "XMAS"},
	[SCAN_UDP] = {udp_send, udp_recv, PORT_UNKNOWN, "UDP"},
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
	t_port_state		s;
	int					h;
	int					t;
	uint16_t			port;

	if (hdr->caplen < off + sizeof(*iph) + sizeof(*tcph))
		return ;
	iph = (const struct iphdr *)(data + off);
	if (iph->protocol != IPPROTO_TCP)
		return ;
	h = find_host_idx(w->opts, iph->saddr);
	if (h < 0)
		return ;
	tcph = (const struct tcphdr *)((const uint8_t *)iph + iph->ihl * 4);
	t = type_for_sport(w, ntohs(tcph->dest));
	if (t < 0)
		return ;
	port = ntohs(tcph->source);
	if (port > MAX_PORTS || !w->opts->ports[port])
		return ;
	s = scan_ops(t)->classify(tcph);
	if (s != PORT_UNKNOWN)
		w->results[h][port].state[t] = s;
}

/*
** Single collection window draining this worker's pcap handle for 1000ms.
** The BPF filter already narrows to TCP replies destined to any of our
** source ports, so handle_reply does the per-packet demultiplexing.
*/
static void	scan_collect_replies(t_worker *w)
{
	uint64_t			deadline;
	size_t				off;
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	int					rc;

	off = dl_header_size(pcap_datalink(w->p));
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
** Send every probe this worker owns for one target port: for each selected
** scan type, mark the slot with that type's no_reply_state and emit the probe
** (from that type's source port) to every host.
*/
static void	send_port_probes(t_worker *w, int port)
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
			}
		}
		t++;
	}
}

/*
** One worker's full pass. It owns every port p where (p - 1) % nthreads == id.
** It fires all probes for all selected scan types across its whole stride
** first, then opens a single collection window — so the cost of waiting for
** replies is paid once for every scan type at once, not once per type.
*/
void	scan_run(t_worker *w)
{
	int	port;

	port = w->id + 1;
	while (port <= MAX_PORTS)
	{
		if (w->opts->ports[port])
			send_port_probes(w, port);
		port += w->nthreads;
	}
	scan_collect_replies(w);
}
