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
** Build an IPv4 + TCP SYN probe into buf. Returns the total length.
** Caller must provide at least sizeof(iphdr)+sizeof(tcphdr) = 40 bytes.
*/
size_t	build_syn_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
		uint16_t sport, uint16_t dport)
{
	struct iphdr	*iph;
	struct tcphdr	*tcph;
	struct s_pseudo	ph;
	uint8_t			pseudo[sizeof(struct s_pseudo) + sizeof(struct tcphdr)];
	size_t			total;

	total = sizeof(*iph) + sizeof(*tcph);
	memset(buf, 0, total);
	iph = (struct iphdr *)buf;
	tcph = (struct tcphdr *)(buf + sizeof(*iph));
	iph->ihl = 5;
	iph->version = 4;
	iph->tot_len = htons(total);
	iph->id = htons((uint16_t)(rand() & 0xffff));
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = src.s_addr;
	iph->daddr = dst.s_addr;
	iph->check = in_cksum(iph, sizeof(*iph));
	tcph->source = htons(sport);
	tcph->dest = htons(dport);
	tcph->seq = htonl((uint32_t)rand());
	tcph->doff = 5;
	tcph->syn = 1;
	tcph->window = htons(1024);
	ph.saddr = src.s_addr;
	ph.daddr = dst.s_addr;
	ph.zero = 0;
	ph.protocol = IPPROTO_TCP;
	ph.len = htons(sizeof(*tcph));
	memcpy(pseudo, &ph, sizeof(ph));
	memcpy(pseudo + sizeof(ph), tcph, sizeof(*tcph));
	tcph->check = in_cksum(pseudo, sizeof(pseudo));
	return (total);
}
