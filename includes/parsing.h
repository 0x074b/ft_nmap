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
}	t_opt_type;

/*
** Parsed command-line options. Filled by parse_opts(), consumed later when
** building a t_config. Types are picked to match what the option carries:
**   - ip: raw host string (IP or FQDN). Validated by resolve_host() at parse
**     time; final resolution happens when building targets.
**   - file: optional path to a hosts file, NULL when --file is absent.
**   - speedup: thread count, 0..MAX_SPEEDUP.
*/
typedef struct s_options
{
	bool	ports[MAX_PORTS + 1];
	char	*ip;
	char	*file;
	int		speedup;
	bool	scan[SCAN_MAX];
}	t_options;

int		parse_opts(int argc, char **argv, t_options *opts);
void	print_help(const char *prog);

int		set_ports(t_options *opts, const char *arg);
int		set_ip(t_options *opts, const char *arg);
int		set_file(t_options *opts, const char *arg);
int		set_speedup(t_options *opts, const char *arg);
int		set_scan(t_options *opts, const char *arg);

int		resolve_host(const char *host, char *out, size_t out_len);

#endif
