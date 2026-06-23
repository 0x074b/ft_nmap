#include <stdio.h>
#include <string.h>

#include "ft_nmap.h"

/*
** Append "<prim> S1 or <prim> S2 or ..." for every source port, e.g. with
** prim "dst port" or "icmp[28:2] ==". Returns the new write offset.
*/
static size_t	append_or_list(char *filter, size_t size, size_t off,
		const char *prim, const uint16_t *sports, int count)
{
	int	i;

	i = 0;
	while (i < count)
	{
		off += (size_t)snprintf(filter + off, size - off, "%s%s %u",
				i ? " or " : "", prim, sports[i]);
		i++;
	}
	return (off);
}

/*
** Build a BPF expression matching only replies that answer THIS worker's
** probes — i.e. destined to one of our (per-thread unique) source ports — so
** workers never capture each other's packets. For TCP/UDP that is a dst-port
** match. ICMP has no ports, so when UDP scanning we instead match the source
** port inside the quoted original datagram (ICMP hdr 8 + inner IP hdr 20 =
** offset 28), gated on type 3 (dest-unreachable); this keeps ICMP scoped to
** this thread too, rather than every handle grabbing all ICMP on the wire.
*/
static void	build_sport_filter(char *filter, size_t size,
		const uint16_t *sports, int count, int udp)
{
	size_t	off;

	off = (size_t)snprintf(filter, size,
		udp ? "((tcp or udp) and (" : "tcp and (");
	off = append_or_list(filter, size, off, "dst port", sports, count);
	if (udp)
	{
		off += (size_t)snprintf(filter + off, size - off,
				")) or (icmp[0] == 3 and (");
		off = append_or_list(filter, size, off, "icmp[28:2] ==", sports, count);
		off += (size_t)snprintf(filter + off, size - off, "))");
	}
	else
		off += (size_t)snprintf(filter + off, size - off, ")");
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
	char				filter[512];
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
	acc->ifdrop += ps.ps_ifdrop;
}
