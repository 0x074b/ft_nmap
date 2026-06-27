#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "ft_nmap.h"

/*
** OS fingerprint storage - one per target host
** Stores characteristics extracted from SYN-ACK responses
*/
typedef struct s_fingerprint
{
	uint8_t		ttl;
	uint16_t	window;
	bool		df;
	uint8_t		tcp_opt_len;
	bool		valid;
	bool		from_synack;  /* Track if from SYN+ACK (vs RST) */
}	t_fingerprint;

/* Store fingerprints for up to MAX_TARGETS hosts */
static t_fingerprint	g_fingerprints[MAX_TARGETS];

/*
** Classify OS family from reconstructed initial TTL.
** Sets *base_conf to the base confidence for this classification.
*/
static const char	*ttl_to_family(uint8_t ttl, int *base_conf)
{
	if (ttl == 64)	{ *base_conf = 45; return ("Linux/Unix"); }
	if (ttl == 128)	{ *base_conf = 45; return ("Windows"); }
	if (ttl == 255)	{ *base_conf = 45; return ("Cisco/Network Device"); }
	if (ttl == 32)	{ *base_conf = 30; return ("Windows (legacy)"); }
	*base_conf = 15;
	return ("Unknown OS");
}

/*
** Refine within Linux/Unix family.
** opt_len ≥ 16: macOS/BSD (more TCP options, e.g. SACK+Timestamps+NOP...)
** window ≥ 32768: modern Linux kernel
*/
static const char	*refine_unix(uint16_t window, uint8_t opt_len, int *extra)
{
	if (opt_len >= 16)
	{
		*extra = 25;
		return ("macOS/FreeBSD");
	}
	if (window >= 32768)
	{
		*extra = 20 + (opt_len >= 12 ? 10 : opt_len >= 4 ? 5 : 0);
		return ("Linux 4.x+");
	}
	if (window >= 16384)
	{
		*extra = 15;
		return ("Linux 3.x");
	}
	if (window >= 8192)
	{
		*extra = 10;
		return ("Linux 2.6.x");
	}
	*extra = 5;
	return ("Linux/Unix");
}

/*
** Refine within Windows family.
*/
static const char	*refine_windows(uint16_t window, int *extra)
{
	if (window >= 64000)
	{
		*extra = 25;
		return ("Windows 10/11/Server 2019+");
	}
	if (window >= 16000)
	{
		*extra = 20;
		return ("Windows Vista/7/8");
	}
	*extra = 15;
	return ("Windows XP/2003");
}

/*
** Refine within Cisco/Network Device family.
*/
static const char	*refine_network(uint16_t window, int *extra)
{
	if (window <= 4096)
	{
		*extra = 25;
		return ("Cisco IOS");
	}
	if (window <= 8192)
	{
		*extra = 20;
		return ("Cisco ASA");
	}
	*extra = 15;
	return ("Network Device/Embedded");
}

/*
** Classify OS directly from a fingerprint using heuristics.
** Confidence is derived from match quality, not looked up from a table.
*/
static void	classify_os(const t_fingerprint *fp, char *out, size_t out_size)
{
	const char	*variant;
	int			base_conf;
	int			extra_conf;
	int			total;

	ttl_to_family(fp->ttl, &base_conf);
	extra_conf = 0;
	if (fp->ttl == 64)
		variant = refine_unix(fp->window, fp->tcp_opt_len, &extra_conf);
	else if (fp->ttl == 128)
		variant = refine_windows(fp->window, &extra_conf);
	else if (fp->ttl == 255)
		variant = refine_network(fp->window, &extra_conf);
	else
		variant = "Unknown OS";
	total = base_conf + extra_conf + (fp->df ? 5 : 0);
	if (total > 99)
		total = 99;
	snprintf(out, out_size, "%s (%d%%)", variant, total);
}
/*
** Extract TCP header options length
** Returns size in bytes of TCP options
*/
static int	extract_tcp_options_len(const struct tcphdr *tcph)
{
	int	doff;
	int	header_len;

	if (!tcph)
		return (0);
	doff = tcph->doff;
	if (doff < 5 || doff > 15)
		return (0);
	header_len = doff * 4;
	return (header_len - sizeof(*tcph));
}

/*
** Reconstruct probable initial TTL
** Common OS TTLs: Linux=64, Windows=128, Cisco=255
** After network hops, received TTL is lower
** We reverse-engineer the initial value
*/
static uint8_t	reconstruct_initial_ttl(uint8_t received_ttl)
{
	int		ttl_candidates[] = {32, 60, 64, 80, 120, 128, 255};
	int		best_ttl;
	int		min_diff;
	int		i;
	int		diff;

	best_ttl = 64;
	min_diff = 256;
	i = 0;
	while (i < 7)
	{
		diff = ttl_candidates[i] - received_ttl;
		if (diff < 0)
			diff = -diff;
		if (diff < min_diff)
		{
			min_diff = diff;
			best_ttl = ttl_candidates[i];
		}
		i++;
	}
	return (best_ttl);
}

/*
** Extract OS fingerprint from TCP packets (SYN-ACK or RST)
** Collects TTL, window size, DF flag, TCP options
** Called when receiving replies from target
** 
** Priority: SYN+ACK > RST (window > 0)
** Ignores: RST with window=0 (invalid responses)
*/
void	os_extract_fingerprint(int host_idx, const struct iphdr *iph,
		const struct tcphdr *tcph)
{
	t_fingerprint	*fp;
	int				opt_len;
	bool			df;
	uint8_t			reconstructed_ttl;
	uint16_t		window;
	bool			is_synack;
	bool			is_rst;

	if (host_idx < 0 || host_idx >= MAX_TARGETS || !iph || !tcph)
		return ;

	fp = &g_fingerprints[host_idx];
	window = ntohs(tcph->window);
	is_synack = (tcph->syn && tcph->ack);
	is_rst = tcph->rst;

	/* Debug: Show every TCP packet received */
	opt_len = extract_tcp_options_len(tcph);
	// printf("Host %d: flags syn=%d ack=%d rst=%d ttl=%u win=%u opt=%d\n",
	// 		host_idx, tcph->syn, tcph->ack, tcph->rst, iph->ttl, window, opt_len);

	/* Ignore invalid packets */
	if (!is_synack && !is_rst)
		return ;

	/* Ignore RST with window=0 (not a valid response) */
	if (is_rst && window == 0)
	{
		// printf("  -> Ignoring RST with window=0 (invalid)\n");
		return ;
	}

	/* SYN+ACK: Always take it, even if we had a RST before */
	if (is_synack)
	{
		fp->ttl = iph->ttl;
		fp->window = window;
		df = (ntohs(iph->frag_off) & 0x4000) != 0;
		fp->df = df;
		fp->tcp_opt_len = (uint8_t)(opt_len & 0xFF);
		reconstructed_ttl = reconstruct_initial_ttl(iph->ttl);
		fp->ttl = reconstructed_ttl;
		fp->valid = true;
		fp->from_synack = true;
		// printf("  -> Stored from SYN+ACK (TTL=%u, Win=%u, OptLen=%u)\n",
		// 		fp->ttl, fp->window, fp->tcp_opt_len);
		return ;
	}

	/* RST: Only take if we haven't already got a SYN+ACK */
	if (is_rst && !fp->from_synack)
	{
		fp->ttl = iph->ttl;
		fp->window = window;
		df = (ntohs(iph->frag_off) & 0x4000) != 0;
		fp->df = df;
		fp->tcp_opt_len = (uint8_t)(opt_len & 0xFF);
		reconstructed_ttl = reconstruct_initial_ttl(iph->ttl);
		fp->ttl = reconstructed_ttl;
		fp->valid = true;
		fp->from_synack = false;
		// printf("  -> Stored from RST (TTL=%u, Win=%u, OptLen=%u)\n",
		// 		fp->ttl, fp->window, fp->tcp_opt_len);
		return ;
	}

	/* We already have a SYN+ACK, ignore this RST */
	if (is_rst && fp->from_synack)
	{
		// printf("  -> Ignoring RST (already have SYN+ACK)\n");
		return ;
	}
}

/*
** Reset global fingerprints array
** Called at start of detection
*/
void	os_detect_init(void)
{
	memset(g_fingerprints, 0, sizeof(g_fingerprints));
}

/*
** Analyze collected fingerprints and generate OS guesses for each host.
** Called after scan completes and all packets captured.
*/
void	os_detect_analyze(t_scan_result **results, size_t ip_count)
{
	size_t			h;
	t_fingerprint	*fp;
	char			buf[128];

	if (!results || ip_count == 0)
		return ;
	for (h = 0; h < ip_count; h++)
	{
		fp = &g_fingerprints[h];
		if (!fp->valid)
			continue ;
		classify_os(fp, buf, sizeof(buf));
		strncpy(results[h][0].service.name, buf, SERVICE_LEN - 1);
		results[h][0].service.detected = true;
	}
}

