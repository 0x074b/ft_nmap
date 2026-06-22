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
** Create and activate a capture handle on iface, non-promiscuous, with a small
** snaplen and an enlarged kernel buffer (see PCAP_* in ft_nmap.h). The
** create/activate flow — rather than pcap_open_live — is what lets us set the
** buffer size before the handle goes live. Returns NULL on error (message
** printed to stderr).
*/
static pcap_t	*create_handle(const char *iface)
{
	char	errbuf[PCAP_ERRBUF_SIZE];
	pcap_t	*p;

	p = pcap_create(iface, errbuf);
	if (!p)
		return (fprintf(stderr, "Error: pcap_create: %s\n", errbuf), NULL);
	pcap_set_snaplen(p, PCAP_SNAPLEN);
	pcap_set_promisc(p, 0);
	pcap_set_timeout(p, 10);
	pcap_set_buffer_size(p, PCAP_BUFFER_SIZE);
	if (pcap_activate(p) < 0)
	{
		fprintf(stderr, "Error: pcap_activate: %s\n", pcap_geterr(p));
		pcap_close(p);
		return (NULL);
	}
	return (p);
}

pcap_t	*pcap_open_for_scan(const char *iface, const uint16_t *sports,
		int count, int udp)
{
	char				errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	fp;
	char				filter[256];
	pcap_t				*p;

	p = create_handle(iface);
	if (!p)
		return (NULL);
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
