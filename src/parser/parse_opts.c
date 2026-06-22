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
	printf("  --speedup[=N]     Number of parallel threads (0-%d,"
		" default %d if flag passed alone)\n",
		MAX_SPEEDUP, MAX_SPEEDUP);
	printf("  --scan TYPES      Scan types: SYN,ACK,FIN,NULL,XMAS,UDP\n");
	printf("  -O, --os-detect   Enable OS detection via fingerprinting\n");
	printf("  -sV, --service-detect Enable service and version detection\n");
}

int	parse_opts(int argc, char **argv, t_options *opts)
{
	static const struct option longopts[] = {
		{"help",		no_argument,		0, OPT_HELP},
		{"ports",		required_argument,	0, OPT_PORTS},
		{"ip",			required_argument,	0, OPT_IP},
		{"file",		required_argument,	0, OPT_FILE},
		{"speedup",		optional_argument,	0, OPT_SPEEDUP},
		{"scan",		required_argument,	0, OPT_SCAN},
		{"os-detect",	no_argument,		0, OPT_OS},
		{"service-detect",no_argument,		0, OPT_SERVICE},
		{0, 0, 0, 0},
	};
	int		opt;
	bool	scan_type_provided = false;
	bool	ports_provided = false;

	memset(opts, 0, sizeof(*opts));
	while ((opt = getopt_long(argc, argv, "hp:i:f:S::s:OV",
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
			ports_provided = true;
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
			if (!optarg)
				opts->speedup = MAX_SPEEDUP;
			else if (set_speedup(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_SCAN:
			if (set_scan(opts, optarg) < 0)
				return (-1);
			scan_type_provided = true;
			break ;
		case OPT_OS:
			opts->os_detection = true;
			break ;
		case OPT_SERVICE:
			opts->service_detection = true;
			break ;
		default:
			print_help(argv[0]);
			return (-1);
		}
	}
	if (opts->ip_count == 0)
	{
		fprintf(stderr, "Error: --ip or --file is required\n");
		print_help(argv[0]);
		return (-1);
	}
	if (!scan_type_provided)
		memset(opts->scan, 1, sizeof(opts->scan));
	if (!ports_provided)
		memset(opts->ports, 1, sizeof(opts->ports));
	return (0);
}
