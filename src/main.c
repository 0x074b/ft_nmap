#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ft_nmap.h"

static t_scan_type	selected_scan_type(const t_options *opts)
{
	int	i;

	i = 0;
	while (i < SCAN_MAX)
	{
		if (opts->scan[i])
			return ((t_scan_type)i);
		i++;
	}
	return (SCAN_MAX);
}

static int	open_raw_socket(void)
{
	int	sock;
	int	on;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock < 0)
	{
		perror("socket");
		return (-1);
	}
	on = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt IP_HDRINCL");
		close(sock);
		return (-1);
	}
	return (sock);
}

static void	scan_targets(const t_options *opts, int sock, pcap_t *p,
		struct in_addr src, uint16_t sport, t_scan_type scan_type,
		t_port_state **results)
{
	t_port_state	state;
	size_t			h;
	int				port;

	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (!opts->ports[port])
				continue ;
			if (scan_port_by_type(scan_type, sock, p, src, sport,
					opts->ips[h].addr, (uint16_t)port, 1000, &state) == 0)
				results[h][port] = state;
			else
				results[h][port] = PORT_FILTERED;
		}
	}
}

static t_port_state	**alloc_results(size_t ip_count)
{
	t_port_state	**r;
	size_t			h;

	r = calloc(ip_count, sizeof(*r));
	if (!r)
		return (NULL);
	for (h = 0; h < ip_count; h++)
	{
		r[h] = calloc(MAX_PORTS + 1, sizeof(**r));
		if (!r[h])
		{
			while (h-- > 0)
				free(r[h]);
			free(r);
			return (NULL);
		}
	}
	return (r);
}

static void	free_results(t_port_state **r, size_t ip_count)
{
	size_t	h;

	for (h = 0; h < ip_count; h++)
		free(r[h]);
	free(r);
}

int	main(int argc, char **argv)
{
	t_options		opts;
	char			iface[IFACE_LEN];
	struct in_addr	src;
	uint16_t		sport;
	int				sock;
	pcap_t			*p;
	t_port_state	**results;
	t_scan_type		scan_type;

	if (parse_opts(argc, argv, &opts) < 0)
		return (1);
	scan_type = selected_scan_type(&opts);
	if (scan_type == SCAN_MAX)
		return (fprintf(stderr, "Error: no scan type selected\n"), 1);
	if (scan_type != SCAN_SYN && scan_type != SCAN_ACK)
		return (fprintf(stderr,
				"Error: selected scan type is not implemented yet\n"), 1);
	if (pick_interface(iface, &src) < 0)
		return (1);
	srand((unsigned int)time(NULL));
	sock = open_raw_socket();
	if (sock < 0)
	{
		fprintf(stderr, "Hint: raw sockets need CAP_NET_RAW (run as root)\n");
		return (1);
	}
	results = alloc_results(opts.ip_count);
	if (!results)
		return (close(sock), 1);
	printf("Scanning from %s (threads=%d)\n", iface, opts.speedup);
	if (opts.speedup == 0)
	{
		sport = (uint16_t)(49152 + (rand() % 16000));
		p = pcap_open_for_scan(iface, sport);
		if (!p)
			return (free_results(results, opts.ip_count),
				close(sock), 1);
		scan_targets(&opts, sock, p, src, sport, scan_type, results);
		pcap_close(p);
	}
	else
	{
		if (run_scan_threaded(&opts, sock, scan_type, iface, src, results) < 0)
			return (free_results(results, opts.ip_count),
				close(sock), 1);
	}
	report_results(&opts, scan_type, results);
	free_results(results, opts.ip_count);
	close(sock);
	return (0);
}
