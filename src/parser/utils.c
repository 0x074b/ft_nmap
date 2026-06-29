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

	res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(host, NULL, &hints, &res);
	if (err != 0)
	{
		fprintf(stderr, "Error: cannot resolve '%s': %s\n",
			host, gai_strerror(err));
		freeaddrinfo(res);
		return (-1);
	}
	addr = (struct sockaddr_in *)res->ai_addr;
	*out = addr->sin_addr;
	freeaddrinfo(res);
	return (0);
}

/*
** Return the index of the first host already resolved to addr, or -1 if none.
** Replies only carry a source IP, so two entries sharing an IP are
** indistinguishable on the wire and their replies would all route to the
** first slot — dedup on the resolved IP keeps that from happening.
*/
static int	find_duplicate_ip(const t_options *opts, struct in_addr addr)
{
	size_t	h;

	h = 0;
	while (h < opts->ip_count)
	{
		if (opts->ips[h].addr.s_addr == addr.s_addr)
			return ((int)h);
		h++;
	}
	return (-1);
}

/*
** Append a single host to opts->ips, growing the array geometrically up to
** MAX_TARGETS. A host that cannot be resolved is reported (by resolve_host)
** and skipped, not fatal, so one bad line in a --file list does not abort the
** whole scan. Hosts resolving to an already-listed IP are likewise skipped:
** scanning the same IP twice yields identical results and the reply routing
** cannot tell duplicate slots apart. Returns -1 only on hard errors (host list
** full, allocation failure) that should stop parsing.
*/
int	add_host(t_options *opts, const char *host)
{
	struct in_addr	addr;
	t_host			*tmp;
	size_t			new_cap;
	int				dup;

	if (opts->ip_count >= MAX_TARGETS)
		return (fprintf(stderr,
				"Error: too many hosts (max %d)\n", MAX_TARGETS), -1);
	if (strlen(host) >= HOST_LEN)
		return (fprintf(stderr, "Error: host too long: %s\n", host), -1);
	if (resolve_host(host, &addr) < 0)
		return (0);
	dup = find_duplicate_ip(opts, addr);
	if (dup >= 0)
		return (fprintf(stderr, "Note: skipping '%s', duplicate of '%s'\n",
				host, opts->ips[dup].input), 0);
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

/*
** Release the dynamically grown ips array and reset the list to empty, so the
** struct is safe to free again or reuse. free(NULL) is a no-op, so calling
** this on an options struct that never allocated any hosts is fine.
*/
void	free_options(t_options *opts)
{
	free(opts->ips);
	opts->ips = NULL;
	opts->ip_count = 0;
	opts->ip_cap = 0;
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

int	set_ttl(t_options *opts, const char *arg)
{
	char	*end;
	long	n;

	errno = 0;
	n = strtol(arg, &end, 10);
	if (errno != 0 || end == arg || *end != '\0' || n < 1 || n > 255)
		return (fprintf(stderr,
				"Error: --ttl must be 1..255 (got '%s')\n", arg), -1);
	opts->custom_ttl = (uint8_t)n;
	return (0);
}

int	set_scan_delay(t_options *opts, const char *arg)
{
	char	*end;
	long	n;

	errno = 0;
	n = strtol(arg, &end, 10);
	if (errno != 0 || end == arg || *end != '\0' || n < 0 || n > 3600000)
		return (fprintf(stderr,
				"Error: --scan-delay must be 0..3600000 ms (got '%s')\n",
				arg), -1);
	opts->scan_delay_ms = (uint32_t)n;
	return (0);
}

int	set_data_length(t_options *opts, const char *arg)
{
	char	*end;
	long	n;

	errno = 0;
	n = strtol(arg, &end, 10);
	if (errno != 0 || end == arg || *end != '\0'
		|| n < 0 || n > MAX_DATA_LENGTH)
		return (fprintf(stderr,
				"Error: --data-length must be 0..%d (got '%s')\n",
				MAX_DATA_LENGTH, arg), -1);
	opts->data_length = (uint16_t)n;
	return (0);
}

/*
** Parse a comma-separated list of IPv4 addresses or FQDNs and add each as a
** decoy. Decoy probes are sent from these source IPs before the real probe,
** making it harder to identify the true scanner.
*/
int	set_decoys(t_options *opts, const char *arg)
{
	const char		*p;
	const char		*comma;
	char			buf[HOST_LEN];
	size_t			len;
	struct in_addr	addr;

	p = arg;
	while (*p)
	{
		comma = strchr(p, ',');
		len = comma ? (size_t)(comma - p) : strlen(p);
		if (len == 0 || len >= sizeof(buf))
			return (fprintf(stderr,
					"Error: invalid decoy in '%s'\n", arg), -1);
		if (opts->decoy_count >= MAX_DECOYS)
			return (fprintf(stderr,
					"Error: too many decoys (max %d)\n", MAX_DECOYS), -1);
		memcpy(buf, p, len);
		buf[len] = '\0';
		if (resolve_host(buf, &addr) < 0)
			return (-1);
		opts->decoys[opts->decoy_count++].ip = addr;
		p += len;
		if (*p == ',')
			p++;
	}
	return (0);
}

/*
** Parse XX:XX:XX:XX:XX:XX and store into opts->fake_mac. Enables AF_PACKET
** sending so the Ethernet source address is spoofed on the wire.
*/
int	set_fake_mac(t_options *opts, const char *arg)
{
	unsigned int	b[6];
	int				i;

	if (sscanf(arg, "%x:%x:%x:%x:%x:%x",
		&b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
		return (fprintf(stderr,
				"Error: --fake-mac must be XX:XX:XX:XX:XX:XX"
				" (got '%s')\n", arg), -1);
	i = 0;
	while (i < 6)
	{
		if (b[i] > 0xff)
			return (fprintf(stderr,
					"Error: invalid MAC byte in '%s'\n", arg), -1);
		opts->fake_mac[i] = (uint8_t)b[i];
		i++;
	}
	opts->fake_mac_set = true;
	return (0);
}
