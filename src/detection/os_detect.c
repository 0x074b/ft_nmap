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
** OS signature database - real nmap has thousands of these
** Each entry represents a known OS fingerprint pattern
*/
typedef struct s_os_db
{
	uint8_t		ttl;
	uint16_t	window;
	bool		df;
	uint8_t		tcp_opt_min;
	uint8_t		tcp_opt_max;
	float		confidence;
	const char	*name;
}	t_os_db;

static const t_os_db	g_os_database[] = {
	/* Linux Kernel 4.x+ (Ubuntu 18.04+, CentOS 8, Debian 10+) */
	{64, 65535, true, 12, 20, 0.95, "Linux 4.x+ (modern)"},
	{64, 32768, true, 12, 20, 0.90, "Linux 3.x-4.x"},
	{64, 16384, true, 12, 16, 0.88, "Linux 2.6.x"},
	{64, 8192, true, 8, 16, 0.85, "Linux (legacy)"},
	
	/* Windows 10 / Server 2016-2019 */
	{128, 65535, true, 12, 20, 0.92, "Windows 10/Server 2016+"},
	{128, 32768, true, 12, 20, 0.89, "Windows 10/Server 2016+"},
	{128, 16384, true, 12, 16, 0.87, "Windows Vista/7/8"},
	{128, 8192, true, 8, 12, 0.82, "Windows XP/2003"},
	
	/* macOS / BSD */
	{64, 65535, true, 16, 20, 0.91, "macOS/FreeBSD (modern)"},
	{64, 32768, true, 12, 20, 0.88, "macOS/BSD"},
	{64, 16384, true, 12, 16, 0.85, "FreeBSD 9.x"},
	
	/* Cisco / Network Devices / Appliances (IOS, ASA, etc.) */
	{255, 4096, true, 8, 16, 0.90, "Cisco IOS"},
	{255, 8192, true, 8, 16, 0.88, "Cisco ASA"},
	{255, 16384, true, 8, 16, 0.87, "Cisco Router/Switch"},
	
	/* AWS/Cloud Instances */
	{64, 26883, true, 12, 20, 0.85, "AWS Linux (custom)"},
	{128, 26883, true, 12, 20, 0.85, "AWS Windows (custom)"},
	
	/* Embedded/UPnP/IoT devices (like the Sonos device in example) */
	{64, 8192, true, 8, 16, 0.80, "Embedded Linux (UPnP)"},
	{64, 16384, true, 8, 20, 0.82, "Embedded Device"},
	
	/* Generic fallback signatures */
	{64, 0, true, 8, 20, 0.70, "Generic Linux/Unix"},
	{128, 0, true, 8, 20, 0.70, "Generic Windows"},
	{255, 0, true, 8, 20, 0.70, "Generic Network Device"},
	
	/* Sentinel */
	{0, 0, false, 0, 0, 0.0, NULL}
};

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
	printf("Host %d: flags syn=%d ack=%d rst=%d ttl=%u win=%u opt=%d\n",
			host_idx, tcph->syn, tcph->ack, tcph->rst, iph->ttl, window, opt_len);

	/* Ignore invalid packets */
	if (!is_synack && !is_rst)
		return ;

	/* Ignore RST with window=0 (not a valid response) */
	if (is_rst && window == 0)
	{
		printf("  -> Ignoring RST with window=0 (invalid)\n");
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
		printf("  -> Stored from SYN+ACK (TTL=%u, Win=%u, OptLen=%u)\n",
				fp->ttl, fp->window, fp->tcp_opt_len);
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
		printf("  -> Stored from RST (TTL=%u, Win=%u, OptLen=%u)\n",
				fp->ttl, fp->window, fp->tcp_opt_len);
		return ;
	}

	/* We already have a SYN+ACK, ignore this RST */
	if (is_rst && fp->from_synack)
	{
		printf("  -> Ignoring RST (already have SYN+ACK)\n");
		return ;
	}
}

/*
** Score a fingerprint against a database entry
** Higher score = better match
** Returns score 0-100
** 
** Exact matches score highest, partial matches lower
*/
static int	score_fingerprint(const t_fingerprint *fp, const t_os_db *db)
{
	int	score = 0;
	int	ttl_diff;

	if (!fp || !db)
		return (0);

	/* TTL matching - exact match is best */
	if (fp->ttl == db->ttl)
		score += 35;
	else
	{
		ttl_diff = fp->ttl - db->ttl;
		if (ttl_diff < 0)
			ttl_diff = -ttl_diff;
		
		/* Penalize but allow close matches */
		if (ttl_diff <= 5)
			score += 20;
		else
			return (0);  /* TTL mismatch is disqualifying */
	}

	/* Window size matching */
	/* If DB has window=0, it's a generic signature - only match on TTL */
	if (db->window == 0)
	{
		score += 10;  /* Generic match */
	}
	/* Exact window match */
	else if (fp->window == db->window)
	{
		score += 30;
	}
	/* Close match (±25%) */
	else if (fp->window > db->window * 0.75 && fp->window < db->window * 1.25)
	{
		score += 15;
	}
	/* Window too different - lower but not disqualifying */
	else if (fp->window > 0)
	{
		score += 5;
	}

	/* DF flag - exact match */
	if (fp->df == db->df)
		score += 15;

	/* TCP options length - within acceptable range */
	if (fp->tcp_opt_len >= db->tcp_opt_min && fp->tcp_opt_len <= db->tcp_opt_max)
	{
		score += 20;
	}
	else if (fp->tcp_opt_len > 0)
	{
		score += 10;  /* Has options but not exact */
	}

	return (score);
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
	int				best_db;
	int				best_score;
	int				score;
	int				i;
	const t_os_db	*db;
	t_fingerprint	*fp;
	char			buf[128];

	if (!results || ip_count == 0)
		return ;

	for (h = 0; h < ip_count; h++)
	{
		fp = &g_fingerprints[h];
		
		/* Debug: Check if fingerprint was collected */
		if (!fp->valid)
		{
			printf("Host %zu: no fingerprint collected\n", h);
			continue ;
		}

		/* Debug: Show what we collected */
		printf("Host %zu: Collected fingerprint - TTL=%u Window=%u DF=%s OptLen=%u (from_synack=%d)\n",
				h, fp->ttl, fp->window, fp->df ? "yes" : "no", fp->tcp_opt_len, fp->from_synack);

		best_db = -1;
		best_score = 0;
		i = 0;

		/* Find best matching signature */
		while (g_os_database[i].name != NULL)
		{
			score = score_fingerprint(fp, &g_os_database[i]);
			if (score > 0)
				printf("  Candidate: %s -> score %d\n", g_os_database[i].name, score);
			if (score > best_score)
			{
				best_score = score;
				best_db = i;
			}
			i++;
		}

		/* Store result if we have ANY confident match (>= 50) */
		if (best_db >= 0 && best_score >= 50)
		{
			db = &g_os_database[best_db];
			snprintf(buf, sizeof(buf), "%s (%.0f%%)",
					db->name, db->confidence * 100.0);
			strncpy(results[h][0].service.name, buf, SERVICE_LEN - 1);
			results[h][0].service.detected = true;
			printf("Host %zu: MATCHED -> %s (score=%d)\n\n", h, buf, best_score);
		}
		else
		{
			/* Show raw fingerprint if no confident match */
			snprintf(buf, sizeof(buf), 
					"TTL=%d Window=%u DF=%s OptLen=%d (unmatched score=%d)",
					fp->ttl, fp->window, fp->df ? "yes" : "no",
					fp->tcp_opt_len, best_score);
			strncpy(results[h][0].service.name, buf, SERVICE_LEN - 1);
			results[h][0].service.detected = true;
			printf("Host %zu: No confident match (best_score=%d)\n\n", h, best_score);
		}
	}
}

