#include <stdlib.h>
#include <string.h>

#include "ft_nmap.h"

/*
** Standard 16-bit one's-complement Internet checksum (RFC 1071). Caller must
** zero the checksum field in the structure before calling.
*/
uint16_t	ip_checksum(const void *data, size_t len)
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
** Fill an IPv4 header shared by every transport. ttl=0 uses the default 64.
** Caller must have zeroed the buffer (the checksum field in particular).
*/
void	build_ip_hdr(struct iphdr *iph, struct in_addr src, struct in_addr dst,
		uint8_t protocol, uint16_t payload_len, uint8_t ttl)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = htons((uint16_t)(sizeof(*iph) + payload_len));
	iph->id = htons((uint16_t)(rand() & 0xffff));
	iph->ttl = ttl ? ttl : 64;
	iph->protocol = protocol;
	iph->saddr = src.s_addr;
	iph->daddr = dst.s_addr;
	iph->check = ip_checksum(iph, sizeof(*iph));
}

/*
** Translate a scan type into its TCP flag set.
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
** TCP checksum over the pseudo-header + TCP header + optional extra data.
** tcph->check must be zero on entry.
*/
static uint16_t	tcp_checksum(const struct tcphdr *tcph, struct in_addr src,
		struct in_addr dst, const uint8_t *extra, size_t extra_len)
{
	struct s_pseudo	ph;
	uint8_t			buf[sizeof(ph) + sizeof(*tcph) + MAX_DATA_LENGTH];

	ph.saddr = src.s_addr;
	ph.daddr = dst.s_addr;
	ph.zero = 0;
	ph.protocol = IPPROTO_TCP;
	ph.len = htons((uint16_t)(sizeof(*tcph) + extra_len));
	memcpy(buf, &ph, sizeof(ph));
	memcpy(buf + sizeof(ph), tcph, sizeof(*tcph));
	if (extra && extra_len)
		memcpy(buf + sizeof(ph) + sizeof(*tcph), extra, extra_len);
	return (ip_checksum(buf, sizeof(ph) + sizeof(*tcph) + extra_len));
}

/*
** Fill a TCP header for the given scan type. Checksum is NOT set here;
** build_tcp_packet computes it after appending any extra data.
** cfg may be NULL (uses defaults: window=1024, no corruption).
*/
void	build_tcp_hdr(struct tcphdr *tcph, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport,
		t_scan_type type, const t_pkt_cfg *cfg)
{
	(void)src;
	(void)dst;
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = htonl((uint32_t)rand());
	tcph->doff = 5;
	if (cfg && cfg->random_window)
		tcph->window = htons((uint16_t)(1024 + (rand() & 0xfbff)));
	else
		tcph->window = htons(1024);
	set_tcp_flags(tcph, type);
}

/*
** Build an IPv4 + TCP probe into buf. Appends data_length random bytes when
** cfg->data_length > 0. Corrupts the checksum when cfg->bad_checksum is set.
** Returns total packet length. buf must be at least MAX_PROBE_LEN bytes.
*/
size_t	build_tcp_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
		uint16_t sport, uint16_t dport, t_scan_type type,
		const t_pkt_cfg *cfg)
{
	struct iphdr	*iph;
	struct tcphdr	*tcph;
	uint8_t			*pad;
	uint16_t		extra;
	size_t			total;
	int				i;

	extra = cfg ? cfg->data_length : 0;
	total = sizeof(*iph) + sizeof(*tcph) + extra;
	memset(buf, 0, total);
	iph = (struct iphdr *)buf;
	tcph = (struct tcphdr *)(buf + sizeof(*iph));
	pad = buf + sizeof(*iph) + sizeof(*tcph);
	build_ip_hdr(iph, src, dst, IPPROTO_TCP,
		(uint16_t)(sizeof(*tcph) + extra), cfg ? cfg->ttl : 0);
	build_tcp_hdr(tcph, src, dst, sport, dport, type, cfg);
	i = 0;
	while (i < extra)
	{
		pad[i] = (uint8_t)(rand() & 0xff);
		i++;
	}
	tcph->check = tcp_checksum(tcph, src, dst, extra > 0 ? pad : NULL, extra);
	if (cfg && cfg->bad_checksum)
		tcph->check ^= 0xffff;
	return (total);
}

static uint16_t	udp_checksum(const struct udphdr *udph,
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
	return (ip_checksum(pseudo, sizeof(pseudo)));
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

/*
** Build an IPv4 + UDP probe into buf. Appends data_length random bytes after
** the payload when cfg->data_length > 0. Returns total packet length.
** buf must be at least MAX_PROBE_LEN bytes.
*/
size_t	build_udp_packet(uint8_t *buf, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport,
		const uint8_t *payload, size_t payload_len,
		const t_pkt_cfg *cfg)
{
	struct iphdr	*iph;
	struct udphdr	*udph;
	uint8_t			*pad;
	uint16_t		extra;
	size_t			total;
	size_t			i;

	extra = cfg ? cfg->data_length : 0;
	total = sizeof(*iph) + sizeof(*udph) + payload_len + extra;
	memset(buf, 0, total);
	iph = (struct iphdr *)buf;
	udph = (struct udphdr *)(buf + sizeof(*iph));
	pad = buf + sizeof(*iph) + sizeof(*udph) + payload_len;
	build_ip_hdr(iph, src, dst, IPPROTO_UDP,
		(uint16_t)(sizeof(*udph) + payload_len + extra), cfg ? cfg->ttl : 0);
	build_udp_hdr(udph, src, dst, sport, dport, payload, payload_len);
	if (payload_len)
		memcpy((uint8_t *)udph + sizeof(*udph), payload, payload_len);
	i = 0;
	while (i < extra)
	{
		pad[i] = (uint8_t)(rand() & 0xff);
		i++;
	}
	return (total);
}

