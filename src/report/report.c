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
** Column header: a fixed PORT column followed by one column per scan type
** the user actually selected, so the table only shows what was scanned.
*/
static void	print_table_header(const t_options *opts)
{
	int	i;

	printf("%-8s", "PORT");
	for (i = 0; i < SCAN_MAX; i++)
		if (opts->scan[i])
			printf("%-15s", scan_type_name((t_scan_type)i));
	printf("SERVICE\n");
}

/*
** A port is worth a row if at least one selected scan type reports something
** other than closed or unknown (i.e. open / filtered / unfiltered / ...).
*/
static int	port_is_interesting(const t_options *opts, const t_scan_result *res)
{
	int	i;

	for (i = 0; i < SCAN_MAX; i++)
	{
		if (!opts->scan[i])
			continue ;
		if (res->state[i] != PORT_CLOSED && res->state[i] != PORT_UNKNOWN)
			return (1);
	}
	return (0);
}

static void	print_port_row(const t_options *opts, const t_scan_result *res)
{
	int	i;

	printf("%-8u", res->port);
	for (i = 0; i < SCAN_MAX; i++)
		if (opts->scan[i])
			printf("%-15s", port_state_name(res->state[i]));
	
	/* Print service if detected */
	if (res->service.detected && res->service.name[0])
		printf("%s", res->service.name);
	else
		printf("-");
	
	printf("\n");
}

static void	report_host(const t_options *opts, size_t h,
		t_scan_result **results)
{
	char	buf[INET_ADDRSTRLEN];
	int		port;
	int		shown;

	inet_ntop(AF_INET, &opts->ips[h].addr, buf, sizeof(buf));
	printf("\nScan report for %s (%s)\n", opts->ips[h].input, buf);
	
	/* Display OS detection result if available */
	if (opts->os_detection && results[h][0].service.detected)
	{
		printf("OS Detection: %s\n", results[h][0].service.name);
	}
	
	print_table_header(opts);
	shown = 0;
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port] && port_is_interesting(opts, &results[h][port]))
		{
			print_port_row(opts, &results[h][port]);
			shown++;
		}
		port++;
	}
	if (shown == 0)
		printf("No open/interesting ports found.\n");
}

/*
** Print the shared results table populated by the scan passes. Walks hosts
** then ports in order so output is deterministic regardless of thread
** scheduling. Each row shows a port's state under every selected scan type.
*/
void	report_results(const t_options *opts, t_scan_result **results)
{
	size_t	h;

	for (h = 0; h < opts->ip_count; h++)
		report_host(opts, h, results);
}

/*
** Summed capture counters across every pcap handle used during the scan.
** A non-zero drop count means the kernel discarded replies we never saw —
** likely inflating the "filtered" tally — so it is worth surfacing.
*/
void	report_pcap_stats(const t_pcap_stats *stats)
{
	printf("\nPackets captured: %lu, dropped (ring): %lu, "
		"dropped (iface/ingest): %lu\n",
		stats->recv, stats->drop, stats->ifdrop);
}
