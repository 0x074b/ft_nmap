#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ft_nmap.h"

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

static t_scan_result	**alloc_results(size_t ip_count)
{
	t_scan_result	**r;
	size_t			h;
	int				port;

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
		for (port = 0; port <= MAX_PORTS; port++)
			r[h][port].port = (uint16_t)port;
	}
	return (r);
}

static void	free_results(t_scan_result **r, size_t ip_count)
{
	size_t	h;

	for (h = 0; h < ip_count; h++)
		free(r[h]);
	free(r);
}

/*
** Run every selected scan type against every target. Each scan type gets a
** full pass through the port-strided path: speedup extra threads plus the
** main thread running one stride itself, so speedup 0 simply means a single
** stride on the main thread (no special-cased sequential path). Results land
** in results[host][port].state[type]. Returns 0 on success, -1 on failure.
*/
static int	run_all_scans(const t_options *opts, int sock, const char *iface,
		struct in_addr src, t_scan_result **results, t_pcap_stats *stats)
{
	int	i;

	for (i = 0; i < SCAN_MAX; i++)
	{
		if (!opts->scan[i])
			continue ;
		if (run_scan_threaded(opts, sock, (t_scan_type)i, iface, src,
				results, stats) < 0)
			return (-1);
	}
	return (0);
}

int	main(int argc, char **argv)
{
	t_options		opts;
	char			iface[IFACE_LEN];
	struct in_addr	src;
	int				sock;
	t_scan_result	**results;
	t_pcap_stats	stats;
	struct timespec	start_ts;
	struct timespec	end_ts;
	double			elapsed_s;

	if (parse_opts(argc, argv, &opts) < 0)
		return (1);
	if (pick_interface(iface, &src) < 0)
		return (1);
	srand((unsigned int)time(NULL));
	sock = open_raw_socket();
	if (sock < 0)
		return (fprintf(stderr,
				"Hint: raw sockets need CAP_NET_RAW (run as root)\n"), 1);
	results = alloc_results(opts.ip_count);
	if (!results)
		return (close(sock), 1);
	stats = (t_pcap_stats){0, 0};
	printf("Scanning from %s (threads=%d)\n", iface, opts.speedup);
	clock_gettime(CLOCK_MONOTONIC, &start_ts);
	if (run_all_scans(&opts, sock, iface, src, results, &stats) < 0)
		return (free_results(results, opts.ip_count), close(sock), 1);
	clock_gettime(CLOCK_MONOTONIC, &end_ts);
	report_results(&opts, results);
	report_pcap_stats(&stats);
	elapsed_s = (double)(end_ts.tv_sec - start_ts.tv_sec)
		+ (double)(end_ts.tv_nsec - start_ts.tv_nsec) / 1000000000.0;
	printf("Scan completed in %.2f seconds\n", elapsed_s);
	free_results(results, opts.ip_count);
	close(sock);
	return (0);
}
