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
** Resolve an IPv4 address or FQDN to its dotted-quad form. Uses getaddrinfo()
** so the same code accepts "10.0.2.15" and "www.google.com".
*/
int	resolve_host(const char *host, char *out, size_t out_len)
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
	if (inet_ntop(AF_INET, &addr->sin_addr, out, out_len) == NULL)
	{
		freeaddrinfo(res);
		return (fprintf(stderr, "Error: inet_ntop: %s\n", strerror(errno)), -1);
	}
	freeaddrinfo(res);
	return (0);
}

int	set_ip(t_options *opts, const char *arg)
{
	char	resolved[INET_ADDRSTRLEN];

	if (strlen(arg) >= HOST_LEN)
		return (fprintf(stderr, "Error: host too long: %s\n", arg), -1);
	if (resolve_host(arg, resolved, sizeof(resolved)) < 0)
		return (-1);
	free(opts->ip);
	opts->ip = strdup(arg);
	if (!opts->ip)
		return (fprintf(stderr, "Error: strdup: %s\n", strerror(errno)), -1);
	return (0);
}

int	set_file(t_options *opts, const char *arg)
{
	FILE	*f;

	f = fopen(arg, "r");
	if (!f)
		return (fprintf(stderr, "Error: cannot open '%s': %s\n",
				arg, strerror(errno)), -1);
	fclose(f);
	free(opts->file);
	opts->file = strdup(arg);
	if (!opts->file)
		return (fprintf(stderr, "Error: strdup: %s\n", strerror(errno)), -1);
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
