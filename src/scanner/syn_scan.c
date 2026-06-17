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
** Classify a captured packet against the expected reply tuple. Returns
** PORT_UNKNOWN if the packet doesn't match our probe (caller should keep
** polling).
*/
static t_port_state	classify_reply(const uint8_t *pkt, size_t len,
		size_t off, struct in_addr expected_src,
		uint16_t expected_sport, uint16_t expected_dport)
{
	const struct iphdr	*iph;
	const struct tcphdr	*tcph;

	if (len < off + sizeof(*iph) + sizeof(*tcph))
		return (PORT_UNKNOWN);
	iph = (const struct iphdr *)(pkt + off);
	if (iph->protocol != IPPROTO_TCP)
		return (PORT_UNKNOWN);
	if (iph->saddr != expected_src.s_addr)
		return (PORT_UNKNOWN);
	tcph = (const struct tcphdr *)((const uint8_t *)iph + iph->ihl * 4);
	if (ntohs(tcph->source) != expected_sport)
		return (PORT_UNKNOWN);
	if (ntohs(tcph->dest) != expected_dport)
		return (PORT_UNKNOWN);
	if (tcph->rst)
		return (PORT_CLOSED);
	if (tcph->syn && tcph->ack)
		return (PORT_OPEN);
	return (PORT_UNKNOWN);
}

/*
** Send one SYN probe to dst:dport and poll the pcap handle until either a
** matching reply arrives or timeout_ms elapses. Verdict written to *state:
** SYN-ACK -> open, RST -> closed, no reply -> filtered.
*/
int	syn_scan_port(int sock, pcap_t *p,
		struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport,
		uint32_t timeout_ms, t_port_state *state)
{
	uint8_t				buf[60];
	size_t				len;
	struct sockaddr_in	to;
	uint64_t			deadline;
	struct pcap_pkthdr	*hdr;
	const u_char		*data;
	size_t				off;
	t_port_state		s;
	int					rc;

	len = build_syn_packet(buf, src, dst, sport, dport);
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	to.sin_port = htons(dport);
	if (sendto(sock, buf, len, 0, (struct sockaddr *)&to, sizeof(to)) < 0)
	{
		perror("sendto");
		return (-1);
	}
	off = dl_header_size(pcap_datalink(p));
	deadline = now_ms() + timeout_ms;
	*state = PORT_FILTERED;
	while (now_ms() < deadline)
	{
		rc = pcap_next_ex(p, &hdr, &data);
		if (rc == 1)
		{
			s = classify_reply(data, hdr->caplen, off, dst, dport, sport);
			if (s != PORT_UNKNOWN)
			{
				*state = s;
				return (0);
			}
		}
		else if (rc == 0)
			usleep(1000);
		else
			break ;
	}
	return (0);
}
