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
		t_port_state state, uint16_t sport)
{
	char	buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	printf("%-32s %-16s %5u  %s			source port used : %u\n", input, buf, port, port_state_name(state), sport);
}
