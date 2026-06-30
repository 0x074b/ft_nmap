#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "ft_nmap.h"

void	print_help(const char *prog)
{
	printf("Usage: %s [--help] [--ports NUMBER/RANGE] --ip IP_ADDRESS"
		" [--file FILE] [--speedup NUMBER] [--scan TYPE]\n", prog);
	printf("  --help                Print this help message\n");
	printf("  --ports PORTS         Ports to scan, e.g. \"80\", \"1-1024\","
		" \"22,80,443\"\n");
	printf("  --ip ADDRESS          Target IPv4 address or FQDN\n");
	printf("  --file PATH           File containing a list of hosts\n");
	printf("  --speedup[=N]         Number of parallel threads (0-%d,"
		" default %d if flag passed alone)\n",
		MAX_SPEEDUP, MAX_SPEEDUP);
	printf("  --scan TYPES          Scan types: SYN,ACK,FIN,NULL,XMAS,UDP\n");
	printf("  -O, --os-detect       Enable OS detection via fingerprinting\n");
	printf("  -V, --service-detect  Enable service and version detection\n");
	printf("Evasion:\n");
	printf("  -f, --fragment        Fragment probes into 8-byte IP fragments\n");
	printf("  -D ip,ip,...          Send decoy probes from the listed IPs\n");
	printf("  --ttl N               Set custom IP TTL (1-255)\n");
	printf("  --scan-delay N        Delay N ms between each probe\n");
	printf("  --window-random       Randomise the TCP window size\n");
	printf("  --bad-checksum        Corrupt TCP checksum (evade some IDS)\n");
	printf("  --data-length N       Append N random bytes of payload\n");
	printf("  --fake-mac XX:XX:...  Spoof source MAC (requires AF_PACKET)\n");
}

int	parse_opts(int argc, char **argv, t_options *opts)
{
	static const struct option longopts[] = {
		{"help",			no_argument,		0, OPT_HELP},
		{"ports",			required_argument,	0, OPT_PORTS},
		{"ip",				required_argument,	0, OPT_IP},
		{"file",			required_argument,	0, OPT_FILE},
		{"speedup",			required_argument,	0, OPT_SPEEDUP},
		{"scan",			required_argument,	0, OPT_SCAN},
		{"os-detect",		no_argument,		0, OPT_OS},
		{"service-detect",	no_argument,		0, OPT_SERVICE},
		{"fragment",		no_argument,		0, OPT_FRAGMENT},
		{"decoy",			required_argument,	0, OPT_DECOY},
		{"scan-delay",		required_argument,	0, OPT_SCAN_DELAY},
		{"ttl",				required_argument,	0, OPT_TTL},
		{"window-random",	no_argument,		0, OPT_WIN_RANDOM},
		{"bad-checksum",	no_argument,		0, OPT_BAD_CKSUM},
		{"data-length",		required_argument,	0, OPT_DATA_LENGTH}, //
		{"fake-mac",		required_argument,	0, OPT_FAKE_MAC}, //
		{0, 0, 0, 0},
	};
	int		opt;
	bool	scan_type_provided = false;
	bool	ports_provided = false;

	memset(opts, 0, sizeof(*opts));
	while ((opt = getopt_long(argc, argv, "hp:i:f:D:S:s:OVL",
				longopts, NULL)) != -1)
	{
		switch (opt)
		{
		case OPT_HELP:
			print_help(argv[0]);
			return (1);
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
			if (set_speedup(opts, optarg) < 0)
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
		case OPT_FRAGMENT:
			opts->fragment = true;
			break ;
		case OPT_DECOY:
			if (set_decoys(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_SCAN_DELAY:
			if (set_scan_delay(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_TTL:
			if (set_ttl(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_WIN_RANDOM:
			opts->random_window = true;
			break ;
		case OPT_BAD_CKSUM:
			opts->bad_checksum = true;
			break ;
		case OPT_DATA_LENGTH:
			if (set_data_length(opts, optarg) < 0)
				return (-1);
			break ;
		case OPT_FAKE_MAC:
			if (set_fake_mac(opts, optarg) < 0)
				return (-1);
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
