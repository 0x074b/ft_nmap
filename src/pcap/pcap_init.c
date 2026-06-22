#include <stdio.h>
#include <string.h>

#include "ft_nmap.h"

/*
** Build a BPF expression matching replies destined to any of our source
** ports. When UDP scanning is enabled, also capture ICMP so UDP port
** unreachable responses can be classified.
*/
static void	build_sport_filter(char *filter, size_t size,
		const uint16_t *sports, int count, int udp)
{
	size_t	off;
	int		i;

	off = (size_t)snprintf(filter, size,
		udp ? "icmp or ((tcp or udp) and (" : "tcp and (");
	i = 0;
	while (i < count)
	{
		off += (size_t)snprintf(filter + off, size - off, "%sdst port %u",
				i ? " or " : "", sports[i]);
		i++;
	}
	off += (size_t)snprintf(filter + off, size - off, udp ? "))" : ")");
}

/*
** Open a live capture handle on iface, non-promiscuous, and install a BPF
** filter narrowing to TCP replies destined to our source ports. Returns NULL
** on error (message printed to stderr).
*/
pcap_t	*pcap_open_for_scan(const char *iface, const uint16_t *sports,
		int count, int udp)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	fp;
	char				filter[256];
	pcap_t				*p;

	p = pcap_open_live(iface, 65535, 0, 10, errbuf);
	if (!p)
		return (fprintf(stderr, "Error: pcap_open_live: %s\n", errbuf), NULL);
	build_sport_filter(filter, sizeof(filter), sports, count, udp);
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

/*
** Read the kernel capture counters off a handle and fold them into acc. Must
** be called while the handle is still open (i.e. just before pcap_close).
** pcap_stats failing (e.g. on some pseudo-interfaces) is non-fatal — we just
** skip that handle's contribution.
*/
void	accumulate_pcap_stats(pcap_t *p, t_pcap_stats *acc)
{
	struct pcap_stat	ps;

	if (pcap_stats(p, &ps) < 0)
		return ;
	acc->recv += ps.ps_recv;
	acc->drop += ps.ps_drop;
}
