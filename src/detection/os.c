#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "ft_nmap.h"

/*
** Simple OS detection heuristic based on IP TTL and TCP window size
** These are common patterns:
** - Linux: TTL 64, window varies
** - Windows: TTL 128, window varies
** - macOS: TTL 64, window varies
** Real nmap uses much more sophisticated fingerprinting.
*/
static const char *guess_os_from_ttl(uint8_t ttl)
{
	if (ttl >= 60 && ttl <= 64)
		return ("Linux/Unix");
	if (ttl >= 120 && ttl <= 128)
		return ("Windows");
	if (ttl >= 250)
		return ("Cisco/Network Device");
	return ("Unknown");
}

static const char *guess_os_from_window(uint16_t window)
{
	/* Very crude heuristic based on initial window size */
	if (window == 1024)
		return ("Linux/Unix");
	if (window == 2048 || window == 4096 || window == 8192 || window == 16384)
		return ("Windows/BSD");
	if (window == 65535)
		return ("BSD");
	return ("Unknown");
}

/*
** Analyze captured packets and generate OS fingerprints for each host.
** In a real implementation, this would parse tons of TCP options,
** fragment behavior, timing patterns, etc. Here we use basic heuristics.
*/
void	analyze_os_fingerprint(const t_options *opts, t_scan_result **results)
{
	size_t			h;
	int				port;

	if (!opts || !results)
		return ;

	/* Stub implementation: OS detection via fingerprinting would require
	 * analyzing captured packets for TTL, window sizes, TCP options, etc.
	 * For now, mark as potentially detectable. */
	
	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (opts->ports[port] && results[h][port].state[SCAN_SYN] == PORT_OPEN)
			{
				/* Could analyze captured packets here */
			}
		}
	}
}
