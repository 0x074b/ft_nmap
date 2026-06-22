#include <stdlib.h>
#include <string.h>

#include "ft_nmap.h"

/*
** Standard 16-bit one's-complement Internet checksum (RFC 1071). Caller must
** zero the checksum field in the structure before calling.
*/
static uint16_t	in_cksum(const void *data, size_t len)
{
	const uint16_t	*p;
	uint32_t		sum;

	p = data;
	sum = 0;
	while (len > 1)
	{
		sum += *p++;
		len -= 2;
	}
	if (len)
		sum += *(const uint8_t *)p;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ((uint16_t)~sum);
}

struct s_pseudo
{
	uint32_t	saddr;
	uint32_t	daddr;
	uint8_t		zero;
	uint8_t		protocol;
	uint16_t	len;
};

/*
** Fill an IPv4 header shared by every transport. protocol selects TCP/UDP
** (and friends); payload_len is the size of the transport segment that
** follows, used to compute tot_len. Owns the IP-header checksum. Caller must
** have zeroed the buffer (the checksum field in particular) beforehand.
*/
void	build_ip_hdr(struct iphdr *iph, struct in_addr src, struct in_addr dst,
		uint8_t protocol, uint16_t payload_len)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = htons((uint16_t)(sizeof(*iph) + payload_len));
	iph->id = htons((uint16_t)(rand() & 0xffff));
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = src.s_addr;
	iph->daddr = dst.s_addr;
	iph->check = in_cksum(iph, sizeof(*iph));
}

/*
** Translate a scan type into its TCP flag set. SYN/ACK/FIN are single flags,
** NULL sets nothing, XMAS lights FIN+PSH+URG. Non-TCP types (UDP) are not
** routed here and leave the header flagless.
*/
static void	set_tcp_flags(struct tcphdr *tcph, t_scan_type type)
{
	if (type == SCAN_SYN)
		tcph->syn = 1;
	else if (type == SCAN_ACK)
		tcph->ack = 1;
	else if (type == SCAN_FIN)
		tcph->fin = 1;
	else if (type == SCAN_XMAS)
	{
		tcph->fin = 1;
		tcph->psh = 1;
		tcph->urg = 1;
	}
}

/*
** TCP checksum over the pseudo-header + TCP header. tcph->check must be zero
** on entry (handled by the zeroed buffer).
*/
static uint16_t	tcp_checksum(const struct tcphdr *tcph, struct in_addr src,
		struct in_addr dst)
{
	struct s_pseudo	ph;
	uint8_t			pseudo[sizeof(struct s_pseudo) + sizeof(struct tcphdr)];

	ph.saddr = src.s_addr;
	ph.daddr = dst.s_addr;
	ph.zero = 0;
	ph.protocol = IPPROTO_TCP;
	ph.len = htons(sizeof(*tcph));
	memcpy(pseudo, &ph, sizeof(ph));
	memcpy(pseudo + sizeof(ph), tcph, sizeof(*tcph));
	return (in_cksum(pseudo, sizeof(pseudo)));
}

/*
** Fill a TCP header for the given scan type (flags driven by set_tcp_flags)
** and stamp its pseudo-header checksum. Caller must have zeroed the buffer.
*/
void	build_tcp_hdr(struct tcphdr *tcph, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport, t_scan_type type)
{
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = htonl((uint32_t)rand());
	tcph->doff = 5;
	tcph->window = htons(1024);
	set_tcp_flags(tcph, type);
	tcph->check = tcp_checksum(tcph, src, dst);
}

/*
** Build an IPv4 + TCP probe for the given scan type into buf. Returns the
** total length. Caller must provide at least sizeof(iphdr)+sizeof(tcphdr) =
** 40 bytes.
*/static uint16_t	udp_checksum(const struct udphdr *udph,
		struct in_addr src, struct in_addr dst,
		const uint8_t *payload, size_t payload_len)
{
	struct s_pseudo	ph;
	uint8_t		pseudo[sizeof(ph) + sizeof(*udph) + payload_len];

	ph.saddr = src.s_addr;
	ph.daddr = dst.s_addr;
	ph.zero = 0;
	ph.protocol = IPPROTO_UDP;
	ph.len = htons((uint16_t)(sizeof(*udph) + payload_len));
	memcpy(pseudo, &ph, sizeof(ph));
	memcpy(pseudo + sizeof(ph), udph, sizeof(*udph));
	if (payload_len)
		memcpy(pseudo + sizeof(ph) + sizeof(*udph), payload, payload_len);
	return (in_cksum(pseudo, sizeof(pseudo)));
}

void	build_udp_hdr(struct udphdr *udph, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport,
		const uint8_t *payload, size_t payload_len)
{
	udph->source = htons(sport);
	udph->dest = htons(dport);
	udph->len = htons((uint16_t)(sizeof(*udph) + payload_len));
	udph->check = 0;
	udph->check = udp_checksum(udph, src, dst, payload, payload_len);
}

size_t	build_udp_packet(uint8_t *buf, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport,
		const uint8_t *payload, size_t payload_len)
{
	struct iphdr	*iph;
	struct udphdr	*udph;
	size_t		total;

	total = sizeof(*iph) + sizeof(*udph) + payload_len;
	memset(buf, 0, total);
	iph = (struct iphdr *)buf;
	udph = (struct udphdr *)(buf + sizeof(*iph));
	build_ip_hdr(iph, src, dst, IPPROTO_UDP,
		(uint16_t)(sizeof(*udph) + payload_len));
	build_udp_hdr(udph, src, dst, sport, dport, payload, payload_len);
	if (payload_len)
		memcpy((uint8_t *)udph + sizeof(*udph), payload, payload_len);
	return (total);
}
size_t	build_tcp_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
		uint16_t sport, uint16_t dport, t_scan_type type)
{
	struct iphdr	*iph;
	struct tcphdr	*tcph;
	size_t			total;

	total = sizeof(*iph) + sizeof(*tcph);
	memset(buf, 0, total);
	iph = (struct iphdr *)buf;
	tcph = (struct tcphdr *)(buf + sizeof(*iph));
	build_ip_hdr(iph, src, dst, IPPROTO_TCP, sizeof(*tcph));
	build_tcp_hdr(tcph, src, dst, sport, dport, type);
	return (total);
}
