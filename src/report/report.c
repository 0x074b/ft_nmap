#include <stdio.h>

#include "ft_nmap.h"

/*
** State aggregation priority — highest first.
**
** UNFILTERED (ACK-scan RST) sits BELOW CLOSED intentionally: an ACK RST only
** tells us there is no stateful firewall in front of the port; it does NOT
** override a SYN/FIN/NULL/XMAS RST that clearly marks the port closed.
** Without this ordering every closed localhost port would aggregate to
** UNFILTERED and pollute the output.
*/
static const t_port_state	g_state_prio[] = {
	PORT_OPEN,
	PORT_FILTERED,
	PORT_OPEN_FILTERED,
	PORT_CLOSED,
	PORT_UNFILTERED,
	PORT_UNKNOWN,
};
# define STATE_PRIO_COUNT	6

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

const char	*scan_type_name(t_scan_type type)
{
	static const char	*const names[SCAN_MAX] = {
		"SYN", "ACK", "FIN", "NULL", "XMAS", "UDP"
	};

	if (type < 0 || type >= SCAN_MAX)
		return ("?");
	return (names[type]);
}

/*
** Aggregate all active scan results for one port into the most informative
** single state, using the priority table above.
*/
static t_port_state	aggregate_state(const t_options *opts,
		const t_scan_result *res)
{
	int	j;
	int	i;

	j = 0;
	while (j < STATE_PRIO_COUNT)
	{
		i = 0;
		while (i < SCAN_MAX)
		{
			if (opts->scan[i] && res->state[i] == g_state_prio[j])
				return (g_state_prio[j]);
			i++;
		}
		j++;
	}
	return (PORT_UNKNOWN);
}

/*
** A port earns a table row only when it might have a reachable service:
** open, open|filtered, or unfiltered (ACK-only firewall probe).
** Filtered and closed ports are suppressed like nmap's default behaviour
** and counted separately in the "Not shown" summary line.
*/
static int	port_is_interesting(const t_options *opts, const t_scan_result *res)
{
	t_port_state	s;

	s = aggregate_state(opts, res);
	return (s == PORT_OPEN || s == PORT_OPEN_FILTERED || s == PORT_UNFILTERED);
}

/*
** Header: fixed PORT column then one column per active scan type, then SERVICE.
*/
static void	print_table_header(const t_options *opts)
{
	int	i;

	printf("%-10s", "PORT");
	i = 0;
	while (i < SCAN_MAX)
	{
		if (opts->scan[i])
			printf("%-15s", scan_type_name((t_scan_type)i));
		i++;
	}
	printf("SERVICE\n");
}

/*
** One row: port/proto, then each active scan type's individual result,
** then the resolved service name.
*/
static void	print_port_row(const t_options *opts, const t_scan_result *res)
{
	char		port_str[24];
	const char	*proto;
	const char	*service;
	int			i;

	/* Protocol: tcp unless only the UDP scan gave a non-UNKNOWN verdict */
	proto = "tcp";
	i = 0;
	while (i < SCAN_MAX)
	{
		if (i != SCAN_UDP && opts->scan[i] && res->state[i] != PORT_UNKNOWN)
			break ;
		i++;
	}
	if (i == SCAN_MAX)
		proto = "udp";

	snprintf(port_str, sizeof(port_str), "%u/%s", res->port, proto);
	printf("%-10s", port_str);

	i = 0;
	while (i < SCAN_MAX)
	{
		if (opts->scan[i])
			printf("%-15s", port_state_name(res->state[i]));
		i++;
	}

	service = (res->service.detected && res->service.name[0])
		? res->service.name : "-";
	printf("%s\n", service);
}

static void	report_host(const t_options *opts, size_t h,
		t_scan_result **results)
{
	char		buf[INET_ADDRSTRLEN];
	int			port;
	int			shown;
	int			not_shown_filtered;
	int			not_shown_closed;
	t_port_state	s;

	inet_ntop(AF_INET, &opts->ips[h].addr, buf, sizeof(buf));
	printf("\nScan report for %s (%s)\n", opts->ips[h].input, buf);

	if (opts->os_detection && results[h][0].service.detected)
		printf("OS Detection: %s\n", results[h][0].service.name);

	shown = 0;
	not_shown_filtered = 0;
	not_shown_closed = 0;
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port])
		{
			if (port_is_interesting(opts, &results[h][port]))
				shown++;
			else
			{
				s = aggregate_state(opts, &results[h][port]);
				if (s == PORT_FILTERED)
					not_shown_filtered++;
				else
					not_shown_closed++;
			}
		}
		port++;
	}
	if (not_shown_filtered > 0 || not_shown_closed > 0)
	{
		printf("Not shown: ");
		if (not_shown_filtered > 0)
			printf("%d filtered port%s",
				not_shown_filtered, not_shown_filtered > 1 ? "s" : "");
		if (not_shown_filtered > 0 && not_shown_closed > 0)
			printf(", ");
		if (not_shown_closed > 0)
			printf("%d closed port%s",
				not_shown_closed, not_shown_closed > 1 ? "s" : "");
		printf("\n");
	}
	if (shown == 0)
	{
		printf("All scanned ports are closed or filtered.\n");
		return ;
	}
	print_table_header(opts);
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port] && port_is_interesting(opts, &results[h][port]))
			print_port_row(opts, &results[h][port]);
		port++;
	}
}

void	report_results(const t_options *opts, t_scan_result **results)
{
	size_t	h;

	h = 0;
	while (h < opts->ip_count)
	{
		report_host(opts, h, results);
		h++;
	}
}

void	report_pcap_stats(const t_pcap_stats *stats)
{
	printf("\nPackets captured: %lu, dropped (ring): %lu, "
		"dropped (iface/ingest): %lu\n",
		stats->recv, stats->drop, stats->ifdrop);
}

