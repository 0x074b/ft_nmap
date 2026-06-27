#include <stdio.h>

#include "ft_nmap.h"

/*
** State aggregation priority — highest first.
** The first state found across all active scan types wins.
*/
static const t_port_state	g_state_prio[] = {
	PORT_OPEN,
	PORT_OPEN_FILTERED,
	PORT_UNFILTERED,
	PORT_FILTERED,
	PORT_CLOSED,
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
** Aggregate all active scan results for one port into the single most
** informative state. Scan types are checked across the priority table;
** the first match anywhere wins — e.g. one OPEN beats 5 FILTERED.
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
** Protocol label for a port: "tcp" when any TCP-family scan type left a
** verdict (even UNKNOWN counts as "it was probed via TCP"), "udp" when only
** the UDP scan was active or only UDP contributed a non-UNKNOWN result.
*/
static const char	*port_proto(const t_options *opts, const t_scan_result *res)
{
	int	i;

	i = 0;
	while (i < SCAN_MAX)
	{
		if (i != SCAN_UDP && opts->scan[i] && res->state[i] != PORT_UNKNOWN)
			return ("tcp");
		i++;
	}
	return ("udp");
}

/*
** A port earns a table row when its aggregate state carries real information.
** CLOSED and UNKNOWN are suppressed — they are counted in the summary line.
*/
static int	port_is_interesting(const t_options *opts, const t_scan_result *res)
{
	t_port_state	s;

	s = aggregate_state(opts, res);
	return (s != PORT_CLOSED && s != PORT_UNKNOWN);
}

static void	print_table_header(void)
{
	printf("%-17s %-14s %s\n", "PORT", "STATE", "SERVICE");
}

static void	print_port_row(const t_options *opts, const t_scan_result *res)
{
	char		port_str[24];
	const char	*service;

	snprintf(port_str, sizeof(port_str), "%u/%s",
		res->port, port_proto(opts, res));
	service = (res->service.detected && res->service.name[0])
		? res->service.name : "-";
	printf("%-17s %-14s %s\n",
		port_str,
		port_state_name(aggregate_state(opts, res)),
		service);
}

static void	report_host(const t_options *opts, size_t h,
		t_scan_result **results)
{
	char	buf[INET_ADDRSTRLEN];
	int		port;
	int		shown;
	int		not_shown;

	inet_ntop(AF_INET, &opts->ips[h].addr, buf, sizeof(buf));
	printf("\nScan report for %s (%s)\n", opts->ips[h].input, buf);

	if (opts->os_detection && results[h][0].service.detected)
		printf("OS Detection: %s\n", results[h][0].service.name);

	shown = 0;
	not_shown = 0;
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port])
		{
			if (port_is_interesting(opts, &results[h][port]))
				shown++;
			else
				not_shown++;
		}
		port++;
	}

	if (not_shown > 0)
		printf("Not shown: %d closed port%s\n",
			not_shown, not_shown > 1 ? "s" : "");

	if (shown == 0)
	{
		printf("All scanned ports are closed.\n");
		return ;
	}

	print_table_header();
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
