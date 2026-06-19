#include <stdio.h>

#include "ft_nmap.h"

typedef struct s_state_counts
{
	int	open;
	int	closed;
	int	filtered;
	int	unfiltered;
	int	unknown;
	int	total;
}t_state_counts;

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

static void	count_state(t_state_counts *counts, t_port_state state)
{
	if (state == PORT_OPEN)
		counts->open++;
	else if (state == PORT_CLOSED)
		counts->closed++;
	else if (state == PORT_FILTERED)
		counts->filtered++;
	else if (state == PORT_UNFILTERED)
		counts->unfiltered++;
	else
		counts->unknown++;
	counts->total++;
}

static void	print_summary_line(struct in_addr addr, int count,
		const char *state_name)
{
	char	buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr, buf, sizeof(buf));
	printf("All %d scanned ports on %s are %s\n", count, buf, state_name);
}

static void	print_not_shown_line(int count, const char *state_name)
{
	if (count > 0)
		printf("Not shown: %d %s ports\n", count, state_name);
}

static void	print_host_heading(const t_options *opts, size_t host_index)
{
	char	buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &opts->ips[host_index].addr, buf, sizeof(buf));
	printf("\nScan report for %s (%s)\n",
		opts->ips[host_index].input, buf);
}

static t_port_state	detail_state_for_scan(t_scan_type scan_type)
{
	if (scan_type == SCAN_ACK)
		return (PORT_FILTERED);
	return (PORT_OPEN);
}

static void	count_host_results(const t_options *opts, t_port_state *host_results,
		t_state_counts *counts)
{
	int	port;

	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port] && host_results[port] != PORT_UNKNOWN)
			count_state(counts, host_results[port]);
		port++;
	}
}

static void	print_host_details(const t_options *opts, size_t host_index,
		t_port_state *host_results, t_port_state detail_state)
{
	int	port;

	printf("%-32s %-16s %5s  %s\n", "INPUT", "ADDR", "PORT", "STATE");
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port] && host_results[port] == detail_state)
			report_port(opts->ips[host_index].input, opts->ips[host_index].addr,
				(uint16_t)port, host_results[port]);
		port++;
	}
}

static void	report_host_syn_ack(const t_options *opts, size_t host_index,
		t_scan_type scan_type, t_port_state *host_results)
{
	t_state_counts	counts;
	t_port_state	 detail_state;
	int			 detailed_count;

	counts = (t_state_counts){0};
	count_host_results(opts, host_results, &counts);
	if (counts.total == 0)
		return ;
	print_host_heading(opts, host_index);
	detail_state = detail_state_for_scan(scan_type);
	if (detail_state == PORT_OPEN)
		detailed_count = counts.open;
	else if (detail_state == PORT_FILTERED)
		detailed_count = counts.filtered;
	else
		detailed_count = counts.unfiltered;
	if (detailed_count == counts.total)
	{
		print_summary_line(opts->ips[host_index].addr, counts.total,
			port_state_name(detail_state));
		return ;
	}
	if (detailed_count == 0)
	{
		if (counts.filtered == counts.total)
			print_summary_line(opts->ips[host_index].addr, counts.total,
				"filtered");
		else if (counts.closed == counts.total)
			print_summary_line(opts->ips[host_index].addr, counts.total,
				"closed");
		else if (counts.unfiltered == counts.total)
			print_summary_line(opts->ips[host_index].addr, counts.total,
				"unfiltered");
		else
		{
			if (counts.filtered > 0)
				print_not_shown_line(counts.filtered, "filtered");
			if (counts.closed > 0)
				print_not_shown_line(counts.closed, "closed");
		}
		return ;
	}
	if (detail_state != PORT_FILTERED && counts.filtered > 0)
		print_not_shown_line(counts.filtered, "filtered");
	if (detail_state != PORT_CLOSED && counts.closed > 0)
		print_not_shown_line(counts.closed, "closed");
	if (detail_state != PORT_UNFILTERED && counts.unfiltered > 0)
		print_not_shown_line(counts.unfiltered, "unfiltered");
	print_host_details(opts, host_index, host_results, detail_state);
}

/*
** Print the shared results table populated by worker threads. Walks hosts
** then ports in order so output is deterministic regardless of thread
** scheduling. Slots left at PORT_UNKNOWN were never probed (port not in
** opts->ports) and are skipped.
*/
void	report_results(const t_options *opts, t_scan_type scan_type,
		t_port_state **results)
{
	size_t	h;

	for (h = 0; h < opts->ip_count; h++)
		report_host_syn_ack(opts, h, scan_type, results[h]);
}
