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

static void	scan_targets(const t_options *opts, int sock, pcap_t *p,
		struct in_addr src, uint16_t sport)
{
	t_port_state	state;
	size_t			h;
	int				port;

	printf("%-32s %-16s %5s  %s\n", "INPUT", "ADDR", "PORT", "STATE");
	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 0; port <= MAX_PORTS; port++)
		{
			if (!opts->ports[port])
				continue ;
			if (syn_scan_port(sock, p, src, sport, opts->ips[h].addr,
					(uint16_t)port, 1000, &state) == 0)
				report_port(opts->ips[h].input, opts->ips[h].addr,
					(uint16_t)port, state);
		}
	}
}

int	main(int argc, char **argv)
{
	t_options		opts;
	char			iface[IFACE_LEN];
	struct in_addr	src;
	uint16_t		sport;
	int				sock;
	pcap_t			*p;

	if (parse_opts(argc, argv, &opts) < 0)
		return (1);
	if (pick_interface(iface, &src) < 0)
		return (1);
	srand((unsigned int)time(NULL));
	sport = (uint16_t)(49152 + (rand() % 16000));
	sock = open_raw_socket();
	if (sock < 0)
	{
		fprintf(stderr, "Hint: raw sockets need CAP_NET_RAW (run as root)\n");
		return (1);
	}
	p = pcap_open_for_scan(iface, sport);
	if (!p)
	{
		close(sock);
		return (1);
	}
	printf("Scanning from %s (src=%s sport=%u)\n",
		iface, inet_ntoa(src), sport);
	scan_targets(&opts, sock, p, src, sport);
	pcap_close(p);
	close(sock);
	return (0);
}
