#ifndef PARSING_H
# define PARSING_H

# include <stdbool.h>
# include <stddef.h>

# include "ft_nmap.h"

# define MAX_SPEEDUP		250

typedef enum e_opt_type
{
	OPT_HELP	= 'h',
	OPT_PORTS	= 'p',
	OPT_IP		= 'i',
	OPT_FILE	= 'f',
	OPT_SPEEDUP	= 'S',
	OPT_SCAN	= 's',
	OPT_OS		= 'O',
}	t_opt_type;

/*
** A single scan target: original user/file string plus the resolved IPv4
** address in network byte order, ready for raw-socket / sockaddr_in use.
*/
typedef struct s_host
{
	char			input[HOST_LEN];
	struct in_addr	addr;
}	t_host;

/*
** Parsed command-line options. Filled by parse_opts(), consumed later when
** building a t_config. Types are picked to match what the option carries:
**   - ips: dynamic array of t_host, cap MAX_TARGETS. Both --ip and --file
**     append to this list; each entry is resolved at parse time so the
**     network code never has to re-parse a string.
**   - speedup: thread count, 0..MAX_SPEEDUP.
*/
typedef struct s_options
{
	bool	ports[MAX_PORTS + 1];
	t_host	*ips;
	size_t	ip_count;
	size_t	ip_cap;
	int		speedup;
	bool	scan[SCAN_MAX];
	bool	os_detection;
}	t_options;

int		parse_opts(int argc, char **argv, t_options *opts);
void	print_help(const char *prog);

int		set_ports(t_options *opts, const char *arg);
int		set_ip(t_options *opts, const char *arg);
int		set_file(t_options *opts, const char *arg);
int		set_speedup(t_options *opts, const char *arg);
int		set_scan(t_options *opts, const char *arg);

int		resolve_host(const char *host, struct in_addr *out);
int		add_host(t_options *opts, const char *host);

#endif
