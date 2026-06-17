#include "parsing.h"
#include <stdio.h>


int		parse_opts(int argc, char **argv, t_options *opts);

static const char	*scan_name(t_scan_type type)
{
	switch (type)
	{
	case SCAN_SYN:	return ("SYN");
	case SCAN_ACK:	return ("ACK");
	case SCAN_FIN:	return ("FIN");
	case SCAN_NULL:	return ("NULL");
	case SCAN_XMAS:	return ("XMAS");
	case SCAN_UDP:	return ("UDP");
	default:		return ("?");
	}
}

void	print_opts(const t_options *opts)
{
	char	buf[INET_ADDRSTRLEN];
	size_t	h;
	int		i;
	int		first;
	int		range_start;

	printf("=== t_options ===\n");
	printf("  ip_count: %zu\n", opts->ip_count);
	printf("  ip_cap:   %zu\n", opts->ip_cap);
	printf("  ips:    ");
	if (opts->ip_count == 0)
		printf(" (none)");
	printf("\n");
	for (h = 0; h < opts->ip_count; h++)
	{
		inet_ntop(AF_INET, &opts->ips[h].addr, buf, sizeof(buf));
		printf("    [%zu] %s -> %s\n", h, opts->ips[h].input, buf);
	}
	printf("  speedup: %d\n", opts->speedup);
	printf("  scans:  ");
	first = 1;
	for (i = 0; i < SCAN_MAX; i++)
	{
		if (opts->scan[i])
		{
			printf("%s%s", first ? " " : ",", scan_name((t_scan_type)i));
			first = 0;
		}
	}
	if (first)
		printf(" (none)");
	printf("\n  ports:  ");
	first = 1;
	range_start = -1;
	for (i = 0; i <= MAX_PORTS + 1; i++)
	{
		int	in_range = (i <= MAX_PORTS && opts->ports[i]);

		if (in_range && range_start < 0)
			range_start = i;
		else if (!in_range && range_start >= 0)
		{
			if (range_start == i - 1)
				printf("%s%d", first ? " " : ",", range_start);
			else
				printf("%s%d-%d", first ? " " : ",", range_start, i - 1);
			first = 0;
			range_start = -1;
		}
	}
	if (first)
		printf(" (none)");
	printf("\n=================\n");
}


int main(int argc, char **argv)
{
	t_options	opts;
	parse_opts(argc, argv, &opts);
	print_opts(&opts);
}