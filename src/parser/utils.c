#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "ft_nmap.h"

static int	parse_port_num(const char *s, char **end, int *port)
{
	long	n;

	errno = 0;
	n = strtol(s, end, 10);
	if (errno != 0 || *end == s)
		return (-1);
	if (n < 0 || n > MAX_PORTS)
		return (-1);
	*port = (int)n;
	return (0);
}

/*
** Accepts comma-separated tokens, each either a single port or a "lo-hi"
** range, e.g. "80", "1-1024", "22,80,443", "1-1024,8080".
*/
int	set_ports(t_options *opts, const char *arg)
{
	char	*p;
	char	*next;
	int		lo;
	int		hi;

	p = (char *)arg;
	while (*p)
	{
		if (parse_port_num(p, &next, &lo) < 0)
			return (fprintf(stderr, "Error: invalid port: %s\n", arg), -1);
		p = next;
		hi = lo;
		if (*p == '-')
		{
			p++;
			if (parse_port_num(p, &next, &hi) < 0)
				return (fprintf(stderr,
						"Error: invalid port range: %s\n", arg), -1);
			p = next;
		}
		if (lo > hi)
			return (fprintf(stderr,
					"Error: invalid port range: %d-%d\n", lo, hi), -1);
		while (lo <= hi)
			opts->ports[lo++] = true;
		if (*p == ',')
			p++;
		else if (*p != '\0')
			return (fprintf(stderr,
					"Error: unexpected character in ports: '%c'\n", *p), -1);
	}
	return (0);
}

/*
** Resolve an IPv4 address or FQDN into a network-order struct in_addr ready
** for raw-socket and sockaddr_in use. Accepts both "10.0.2.15" and
** "www.google.com" via getaddrinfo().
*/
int	resolve_host(const char *host, struct in_addr *out)
{
	struct addrinfo		hints;
	struct addrinfo		*res;
	struct sockaddr_in	*addr;
	int					err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, NULL, &hints, &res);
	if (err != 0)
		return (fprintf(stderr, "Error: cannot resolve '%s': %s\n",
				host, gai_strerror(err)), -1);
	addr = (struct sockaddr_in *)res->ai_addr;
	*out = addr->sin_addr;
	freeaddrinfo(res);
	return (0);
}

/*
** Append a single host to opts->ips. Resolves it up front so failures
** abort parsing early, and grows the ips array geometrically up to
** MAX_TARGETS.
*/
int	add_host(t_options *opts, const char *host)
{
	struct in_addr	addr;
	t_host			*tmp;
	size_t			new_cap;

	if (opts->ip_count >= MAX_TARGETS)
		return (fprintf(stderr,
				"Error: too many hosts (max %d)\n", MAX_TARGETS), -1);
	if (strlen(host) >= HOST_LEN)
		return (fprintf(stderr, "Error: host too long: %s\n", host), -1);
	if (resolve_host(host, &addr) < 0)
		return (-1);
	if (opts->ip_count >= opts->ip_cap)
	{
		new_cap = opts->ip_cap ? opts->ip_cap * 2 : 8;
		if (new_cap > MAX_TARGETS)
			new_cap = MAX_TARGETS;
		tmp = realloc(opts->ips, new_cap * sizeof(*tmp));
		if (!tmp)
			return (fprintf(stderr,
					"Error: realloc: %s\n", strerror(errno)), -1);
		opts->ips = tmp;
		opts->ip_cap = new_cap;
	}
	memset(&opts->ips[opts->ip_count], 0, sizeof(t_host));
	strncpy(opts->ips[opts->ip_count].input, host, HOST_LEN - 1);
	opts->ips[opts->ip_count].addr = addr;
	opts->ip_count++;
	return (0);
}

int	set_ip(t_options *opts, const char *arg)
{
	return (add_host(opts, arg));
}

/*
** Read a hosts file, one host per line. Blank lines and lines starting with
** '#' are skipped. Each host is resolved and appended to opts->ips.
*/
int	set_file(t_options *opts, const char *arg)
{
	FILE	*f;
	char	line[HOST_LEN];
	char	*start;
	size_t	len;

	f = fopen(arg, "r");
	if (!f)
		return (fprintf(stderr, "Error: cannot open '%s': %s\n",
				arg, strerror(errno)), -1);
	while (fgets(line, sizeof(line), f))
	{
		len = strlen(line);
		while (len > 0 && isspace((unsigned char)line[len - 1]))
			line[--len] = '\0';
		start = line;
		while (*start && isspace((unsigned char)*start))
			start++;
		if (*start == '\0' || *start == '#')
			continue ;
		if (add_host(opts, start) < 0)
		{
			fclose(f);
			return (-1);
		}
	}
	fclose(f);
	return (0);
}

int	set_speedup(t_options *opts, const char *arg)
{
	char	*end;
	long	n;

	errno = 0;
	n = strtol(arg, &end, 10);
	if (errno != 0 || end == arg || *end != '\0'
		|| n < 0 || n > MAX_SPEEDUP)
		return (fprintf(stderr,
				"Error: --speedup must be 0..%d (got '%s')\n",
				MAX_SPEEDUP, arg), -1);
	opts->speedup = (int)n;
	return (0);
}

static int	match_scan_type(const char *name, t_scan_type *out)
{
	static const struct s_map {
		const char	*name;
		t_scan_type	type;
	}	map[] = {
		{"SYN",		SCAN_SYN},
		{"ACK",		SCAN_ACK},
		{"FIN",		SCAN_FIN},
		{"NULL",	SCAN_NULL},
		{"XMAS",	SCAN_XMAS},
		{"UDP",		SCAN_UDP},
	};
	size_t		i;

	i = 0;
	while (i < sizeof(map) / sizeof(map[0]))
	{
		if (strcasecmp(name, map[i].name) == 0)
		{
			*out = map[i].type;
			return (0);
		}
		i++;
	}
	return (-1);
}

/*
** Comma-separated list of scan types, e.g. "SYN", "SYN,ACK,UDP".
*/
int	set_scan(t_options *opts, const char *arg)
{
	char		buf[64];
	const char	*p;
	const char	*comma;
	size_t		len;
	t_scan_type	type;

	p = arg;
	while (*p)
	{
		comma = strchr(p, ',');
		len = comma ? (size_t)(comma - p) : strlen(p);
		if (len == 0 || len >= sizeof(buf))
			return (fprintf(stderr,
					"Error: invalid scan token in '%s'\n", arg), -1);
		memcpy(buf, p, len);
		buf[len] = '\0';
		if (match_scan_type(buf, &type) < 0)
			return (fprintf(stderr,
					"Error: unknown scan type '%s'\n", buf), -1);
		opts->scan[type] = true;
		p += len;
		if (*p == ',')
			p++;
	}
	return (0);
}
