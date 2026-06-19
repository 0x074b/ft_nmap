#include <stdio.h>

#include "ft_nmap.h"

const char	*port_state_name(t_port_state s)
{
	if (s == PORT_OPEN)
		return ("open");
	if (s == PORT_CLOSED)
		return ("closed");
	if (s == PORT_FILTERED)
		return ("filtered");
	if (s == PORT_UNFILTERED)
		return ("unfiltered");
	if (s == PORT_OPEN_FILTERED)
		return ("open|filtered");
	return ("unknown");
}

void	report_port(const char *input, struct in_addr addr, uint16_t port,
		t_port_state state)
{
	char	buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	printf("%-32s %-16s %5u  %s\n", input, buf, port, port_state_name(state));
}

/*
** Print the shared results table populated by worker threads. Walks hosts
** then ports in order so output is deterministic regardless of thread
** scheduling. Slots left at PORT_UNKNOWN were never probed (port not in
** opts->ports) and are skipped.
*/
void	report_results(const t_options *opts, t_port_state **results)
{
	size_t	h;
	int		port;

	printf("%-32s %-16s %5s  %s\n", "INPUT", "ADDR", "PORT", "STATE");
	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (!opts->ports[port])
				continue ;
			if (results[h][port] == PORT_UNKNOWN)
				continue ;
			report_port(opts->ips[h].input, opts->ips[h].addr,
				(uint16_t)port, results[h][port]);
		}
	}
}
