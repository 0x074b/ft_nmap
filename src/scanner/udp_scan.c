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

static t_port_state	classify_icmp_unreach(uint8_t code)
{
	if (code == 3)
		return (PORT_CLOSED);
	if (code == 1 || code == 2 || code == 9 || code == 10 || code == 13)
		return (PORT_FILTERED);
	return (PORT_FILTERED);
}

static t_port_state	classify_udp_reply(const uint8_t *pkt, size_t len,
		size_t off, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	const struct iphdr		*iph;
	const struct udphdr		*udph;
	const struct icmphdr	*icmph;
	const struct iphdr		*inner_iph;
	const struct udphdr		*inner_udph;
	size_t					ihl;
	size_t					inner_ihl;

	if (len < off + sizeof(*iph))
		return (PORT_UNKNOWN);
	iph = (const struct iphdr *)(pkt + off);
	ihl = iph->ihl * 4;
	if (len < off + ihl)
		return (PORT_UNKNOWN);
	if (iph->protocol == IPPROTO_UDP)
	{
		if (len < off + ihl + sizeof(*udph))
			return (PORT_UNKNOWN);
		udph = (const struct udphdr *)((const uint8_t *)iph + ihl);
		if (iph->saddr != dst.s_addr)
			return (PORT_UNKNOWN);
		if (ntohs(udph->source) != dport || ntohs(udph->dest) != sport)
			return (PORT_UNKNOWN);
		return (PORT_OPEN);
	}
	if (iph->protocol != IPPROTO_ICMP || len < off + ihl + sizeof(*icmph))
		return (PORT_UNKNOWN);
	icmph = (const struct icmphdr *)((const uint8_t *)iph + ihl);
	if (icmph->type != ICMP_DEST_UNREACH
		|| len < off + ihl + sizeof(*icmph) + sizeof(*inner_iph))
		return (PORT_UNKNOWN);
	inner_iph = (const struct iphdr *)((const uint8_t *)icmph + sizeof(*icmph));
	inner_ihl = inner_iph->ihl * 4;
	if (len < off + ihl + sizeof(*icmph) + inner_ihl + sizeof(*inner_udph))
		return (PORT_UNKNOWN);
	if (inner_iph->protocol != IPPROTO_UDP)
		return (PORT_UNKNOWN);
	inner_udph = (const struct udphdr *)((const uint8_t *)inner_iph + inner_ihl);
	if (inner_iph->saddr != src.s_addr || inner_iph->daddr != dst.s_addr)
		return (PORT_UNKNOWN);
	if (ntohs(inner_udph->source) != sport || ntohs(inner_udph->dest) != dport)
		return (PORT_UNKNOWN);
	return (classify_icmp_unreach(icmph->code));
}

int	udp_scan_port(int sock, pcap_t *p,
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

	len = build_udp_packet(buf, src, dst, sport, dport);
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
	*state = PORT_OPEN_FILTERED;
	while (now_ms() < deadline)
	{
		rc = pcap_next_ex(p, &hdr, &data);
		if (rc == 1)
		{
			s = classify_udp_reply(data, hdr->caplen, off, src, sport, dst, dport);
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
