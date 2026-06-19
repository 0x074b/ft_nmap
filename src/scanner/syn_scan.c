#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "ft_nmap.h"

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
** Send a single crafted SYN to dst:dport. No waiting, no classification —
** the caller is responsible for collecting replies separately via
** syn_collect_replies(). Returns 0 on success, -1 if sendto failed.
*/
int	syn_send_probe(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t				buf[60];
	size_t				len;
	struct sockaddr_in	to;

	len = build_syn_packet(buf, src, dst, sport, dport);
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	to.sin_port = htons(dport);
	if (sendto(sock, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
		return (-1);
	return (0);
}

/*
** Listen on the pcap handle until timeout_ms elapses, writing each
** classified reply into results[h][port]. The BPF filter already narrows
** to TCP packets destined to sport, so we only do the per-packet
** demultiplexing here: saddr -> host index, source port -> target port,
** RST -> closed, SYN+ACK -> open. Slots that never get rewritten keep
** whatever value syn_scan_stride pre-filled them with (PORT_FILTERED).
*/
void	syn_collect_replies(pcap_t *p, uint32_t timeout_ms,
		const t_options *opts, uint16_t sport,
		t_port_state **results)
{
	uint64_t			deadline;
	size_t				off;
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	const struct iphdr	*iph;
	const struct tcphdr	*tcph;
	int					rc;
	int					h;
	uint16_t			port;

	off = dl_header_size(pcap_datalink(p));
	deadline = now_ms() + timeout_ms;
	while (now_ms() < deadline)
	{
		rc = pcap_next_ex(p, &hdr, &data);
		if (rc == 0)
		{
			usleep(1000);
			continue ;
		}
		if (rc < 0)
			break ;
		if (hdr->caplen < off + sizeof(*iph) + sizeof(*tcph))
			continue ;
		iph = (const struct iphdr *)(data + off);
		if (iph->protocol != IPPROTO_TCP)
			continue ;
		h = find_host_idx(opts, iph->saddr);
		if (h < 0)
			continue ;
		tcph = (const struct tcphdr *)((const uint8_t *)iph + iph->ihl * 4);
		if (ntohs(tcph->dest) != sport)
			continue ;
		port = ntohs(tcph->source);
		if (port > MAX_PORTS || !opts->ports[port])
			continue ;
		if (tcph->rst)
			results[h][port] = PORT_CLOSED;
		else if (tcph->syn && tcph->ack)
			results[h][port] = PORT_OPEN;
	}
}

/*
** Fire-then-listen primitive used by both the threaded and sequential
** scan paths. stride_id/stride_total partition the port space: this call
** owns every port p where (p - 1) % stride_total == stride_id. For each
** owned port that opts->ports[] selects, send a SYN to every host, pre-
** marking the slot PORT_FILTERED. Then drain the pcap handle for
** timeout_ms; any reply rewrites the slot to OPEN or CLOSED.
**
** The 1000ms collection window starts after the last probe is sent so
** every probe gets a full reply window.
*/
void	syn_scan_stride(int sock, pcap_t *p, struct in_addr src,
		uint16_t sport, const t_options *opts,
		int stride_id, int stride_total,
		t_port_state **results)
{
	size_t	h;
	int		port;

	port = stride_id + 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port])
		{
			for (h = 0; h < opts->ip_count; h++)
			{
				results[h][port] = PORT_FILTERED;
				syn_send_probe(sock, src, sport,
					opts->ips[h].addr, (uint16_t)port);
			}
		}
		port += stride_total;
	}
	syn_collect_replies(p, 1000, opts, sport, results);
}
