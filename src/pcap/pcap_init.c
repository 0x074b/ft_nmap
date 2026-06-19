#include <stdio.h>
#include <string.h>

#include "ft_nmap.h"

/*
** Open a live capture handle on iface, non-promiscuous, and install a BPF
** filter narrowing to TCP replies destined to our source port. Returns NULL
** on error (message printed to stderr).
*/
pcap_t	*pcap_open_for_scan(const char *iface, uint16_t sport)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	fp;
	char				filter[64];
	pcap_t				*p;

	p = pcap_open_live(iface, 65535, 0, 10, errbuf);
	if (!p)
		return (fprintf(stderr, "Error: pcap_open_live: %s\n", errbuf), NULL);
	snprintf(filter, sizeof(filter),
		"(tcp and dst port %u) or (udp and dst port %u) or icmp",
		sport, sport);
	if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) < 0)
	{
		fprintf(stderr, "Error: pcap_compile: %s\n", pcap_geterr(p));
		pcap_close(p);
		return (NULL);
	}
	if (pcap_setfilter(p, &fp) < 0)
	{
		fprintf(stderr, "Error: pcap_setfilter: %s\n", pcap_geterr(p));
		pcap_freecode(&fp);
		pcap_close(p);
		return (NULL);
	}
	pcap_freecode(&fp);
	if (pcap_setnonblock(p, 1, errbuf) < 0)
	{
		fprintf(stderr, "Error: pcap_setnonblock: %s\n", errbuf);
		pcap_close(p);
		return (NULL);
	}
	return (p);
}
