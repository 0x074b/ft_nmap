#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "ft_nmap.h"

/*
** Simple OS detection based on common port patterns.
** Real nmap uses complex TCP/IP fingerprinting via specialized probes.
** This is a basic heuristic implementation.
*/

/*
** Analyze which ports are open to make OS guesses.
** Real implementation would use packet fingerprinting data.
*/
void	os_detect_analyze(t_scan_result **results, size_t ip_count)
{
	size_t	h;
	int		port;
	int		open_ssh, open_http, open_smb, open_rpc;
	int		open_linux_services, open_win_services;
	const char	*guess;

	if (!results || ip_count == 0)
		return ;

	for (h = 0; h < ip_count; h++)
	{
		open_ssh = 0;
		open_http = 0;
		open_smb = 0;
		open_rpc = 0;
		guess = NULL;

		/* Scan for common services */
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (!results[h][port].port || results[h][port].state[SCAN_SYN] != PORT_OPEN)
				continue ;
			
			/* Common Linux/Unix services */
			if (port == 22)
				open_ssh = 1;
			else if (port == 80 || port == 443 || port == 8080)
				open_http = 1;
			
			/* Common Windows services */
			if (port == 445 || port == 139)
				open_smb = 1;
			else if (port == 135 || port == 593)
				open_rpc = 1;
		}

		open_linux_services = open_ssh + open_http;
		open_win_services = open_smb + open_rpc;

		/* Make educated guess based on service patterns */
		if (open_win_services > 0 && open_linux_services == 0)
			guess = "Windows (SMB detected)";
		else if (open_ssh > 0 && open_smb == 0)
			guess = "Linux/Unix (SSH detected)";
		else if (open_rpc > 0 && open_ssh == 0)
			guess = "Windows (RPC detected)";
		else if (open_linux_services > 0 && open_win_services == 0)
			guess = "Linux/Unix";
		else if (open_win_services > 0 && open_linux_services > 0)
			guess = "Unknown (mixed services)";
		else
			guess = NULL;

		/* Store OS guess in results[h][0].service field */
		if (guess != NULL)
		{
			strncpy(results[h][0].service.name, guess, SERVICE_LEN - 1);
			results[h][0].service.detected = true;
		}
	}
}

/*
** Stub function for extracting fingerprints from packets.
** Real implementation would parse TCP options, TTL, window sizes, etc.
*/
int	os_extract_fingerprint(const struct iphdr *iph,
		const struct tcphdr *tcph, t_os_signature *os_sig)
{
	(void)iph;
	(void)tcph;
	(void)os_sig;
	/* Stub - passive fingerprinting would happen here */
	return (0);
}

