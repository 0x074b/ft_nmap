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

const char	*scan_type_name(t_scan_type t)
{
	if (t == SCAN_SYN)
		return ("SYN");
	if (t == SCAN_ACK)
		return ("ACK");
	if (t == SCAN_FIN)
		return ("FIN");
	if (t == SCAN_NULL)
		return ("NULL");
	if (t == SCAN_XMAS)
		return ("XMAS");
	if (t == SCAN_UDP)
		return ("UDP");
	return ("UNKNOWN");
}

void	report_port(const char *input, struct in_addr addr, t_scan_type type,
		uint16_t port, t_port_state state, uint16_t sport)
{
	char	buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	printf("%-8s %-32s %-16s %5u  %s\tsource port used : %u\n",
		scan_type_name(type), input, buf, port, port_state_name(state), sport);
}
