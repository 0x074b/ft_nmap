#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "ft_nmap.h"

void	print_help(const char *prog)
{
	printf("Usage: %s [--help] [--ports NUMBER/RANGE] --ip IP_ADDRESS"
		" [--file FILE] [--speedup NUMBER] [--scan TYPE]\n", prog);
	printf("  --help            Print this help message\n");
	printf("  --ports PORTS     Ports to scan, e.g. \"80\", \"1-1024\","
		" \"22,80,443\"\n");
	printf("  --ip ADDRESS      Target IPv4 address or FQDN\n");
	printf("  --file PATH       File containing a list of hosts\n");
	printf("  --speedup N       Number of parallel threads (0-%d)\n",
		MAX_SPEEDUP);
	printf("  --scan TYPES      Scan types: SYN,ACK,FIN,NULL,XMAS,UDP\n");
}

int	parse_opts(int argc, char **argv, t_options *opts)
{
	static const struct option longopts[] = {
		{"help",	no_argument,		0, OPT_HELP},
		{"ports",	required_argument,	0, OPT_PORTS},
		{"ip",		required_argument,	0, OPT_IP},
		{"file",	required_argument,	0, OPT_FILE},
		{"speedup",	required_argument,	0, OPT_SPEEDUP},
		{"scan",	required_argument,	0, OPT_SCAN},
		{0, 0, 0, 0},
	};
	int	opt;

	memset(opts, 0, sizeof(*opts));
	while ((opt = getopt_long(argc, argv, "hp:i:f:S:s:",
				longopts, NULL)) != -1)
	{
		switch (opt)
		{
		case OPT_HELP:
			print_help(argv[0]);
			return (0);
		case OPT_PORTS:
			if (set_ports(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_IP:
			if (set_ip(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_FILE:
			if (set_file(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_SPEEDUP:
			if (set_speedup(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_SCAN:
			if (set_scan(opts, optarg) < 0)
				return (-1);
			break ;
		default:
			print_help(argv[0]);
			return (-1);
		}
	}
	if (!opts->ip && !opts->file)
	{
		fprintf(stderr, "Error: --ip or --file is required\n");
		print_help(argv[0]);
		return (-1);
	}
	return (0);
}
