#ifndef PARSING_H
# define PARSING_H

# include <stdbool.h>
# include <stddef.h>

# include "ft_nmap.h"

# define MAX_SPEEDUP		250

typedef enum e_opt_type
{
	OPT_HELP		= 'h',
	OPT_PORTS		= 'p',
	OPT_IP			= 'i',
	OPT_FILE		= 300,	/* long-only, frees short -f for --fragment */
	OPT_SPEEDUP		= 'S',
	OPT_SCAN		= 's',
	OPT_OS			= 'O',
	OPT_SERVICE		= 'V',
	OPT_FRAGMENT	= 'f',	/* -f: split probes into IP fragments */
	OPT_DECOY		= 'D',	/* -D ip,ip,...: send from decoy IPs first */
	OPT_SCAN_DELAY	= 301,	/* --scan-delay N: ms between probes */
	OPT_TTL			= 302,	/* --ttl N: custom IP TTL */
	OPT_WIN_RANDOM	= 303,	/* --window-random: random TCP window */
	OPT_BAD_CKSUM	= 304,	/* --bad-checksum: corrupt checksum */
	OPT_DATA_LENGTH	= 305,	/* --data-length N: extra padding bytes */
	OPT_FAKE_MAC	= 306,	/* --fake-mac XX:XX:XX:XX:XX:XX */
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
	bool		ports[MAX_PORTS + 1];
	t_host		*ips;
	size_t		ip_count;
	size_t		ip_cap;
	int			speedup;
	bool		scan[SCAN_MAX];
	bool		os_detection;
	bool		service_detection;
	/* evasion flags */
	bool		fragment;		/* -f: split probes into 8-byte IP fragments */
	bool		random_window;	/* --window-random: randomise TCP window */
	bool		bad_checksum;	/* --bad-checksum: corrupt TCP/UDP checksum */
	uint8_t		custom_ttl;		/* --ttl N: IP TTL (0 = default 64) */
	uint32_t	scan_delay_ms;	/* --scan-delay N: ms between probes */
	uint16_t	data_length;	/* --data-length N: extra padding bytes */
	t_decoy		decoys[MAX_DECOYS];	/* -D: list of decoy source IPs */
	int			decoy_count;
	uint8_t		fake_mac[6];	/* --fake-mac: source MAC override */
	bool		fake_mac_set;
}	t_options;

int		parse_opts(int argc, char **argv, t_options *opts);
void	print_help(const char *prog);

int		set_ports(t_options *opts, const char *arg);
int		set_ip(t_options *opts, const char *arg);
int		set_file(t_options *opts, const char *arg);
int		set_speedup(t_options *opts, const char *arg);
int		set_scan(t_options *opts, const char *arg);
int		set_ttl(t_options *opts, const char *arg);
int		set_scan_delay(t_options *opts, const char *arg);
int		set_decoys(t_options *opts, const char *arg);
int		set_data_length(t_options *opts, const char *arg);
int		set_fake_mac(t_options *opts, const char *arg);

int		resolve_host(const char *host, struct in_addr *out);
int		add_host(t_options *opts, const char *host);
void	free_options(t_options *opts);

#endif
