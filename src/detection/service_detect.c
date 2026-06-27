#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <ctype.h>
#include <netdb.h>

#include "ft_nmap.h"

#define SERVICE_PROBE_TIMEOUT 2
#define SERVICE_BUFFER_SIZE 4096

/*
** Probe table: maps port -> probe data to send
*/
typedef struct s_probe
{
	uint16_t	port;
	const char	*name;
	const char	*probe_data;
	size_t		probe_len;
}	t_probe;

/* Service probe database */
static const t_probe	g_probes[] = {
	{
		21,
		"ftp",
		"USER nmap\r\n",
		12
	},
	{
		22,
		"ssh",
		"SSH-2.0-OpenSSH_Nmap_Probe\r\n",
		28
	},
	{
		25,
		"smtp",
		"EHLO nmap\r\n",
		11
	},
	{
		53,
		"dns",
		"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
		29
	},
	{
		80,
		"http",
		"GET / HTTP/1.0\r\nHost: nmap\r\nConnection: close\r\n\r\n",
		53
	},
	{
		110,
		"pop3",
		"USER nmap\r\n",
		11
	},
	{
		143,
		"imap",
		"A1 CAPABILITY\r\n",
		15
	},
	{
		443,
		"https",
		"GET / HTTP/1.0\r\nHost: nmap\r\nConnection: close\r\n\r\n",
		53
	},
	{
		/*
		** Portmapper / rpcbind: record-mark framing + RPC NULL call.
		** Fragment header (last frag bit + 40-byte body), XID, CALL, rpcvers 2,
		** prog 100000 (PORTMAP), vers 2, proc 0 (NULL), AUTH_NULL cred+verif.
		*/
		111,
		"rpcbind",
		"\x80\x00\x00\x28"
		"\x72\xfe\x1d\x13"
		"\x00\x00\x00\x00"
		"\x00\x00\x00\x02"
		"\x00\x01\x86\xa0"
		"\x00\x00\x00\x02"
		"\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00"
		"\x00\x00\x00\x00\x00\x00\x00\x00",
		44
	},
	{
		/* CUPS exposes an HTTP-like interface on 631 — same GET probe works. */
		631,
		"ipp",
		"GET / HTTP/1.0\r\nHost: nmap\r\nConnection: close\r\n\r\n",
		53
	},
	{
		3306,
		"mysql",
		"",
		0
	},
	{
		5432,
		"postgresql",
		"",
		0
	},
	{
		0,
		NULL,
		NULL,
		0
	}
};

/*
** Parse IPP/CUPS response: extract the Server header just like HTTP, but
** label it "IPP:" so it is clear this came from an IPP service.
*/
static void	parse_ipp_response(const char *response, char *service_str)
{
	const char	*p;
	const char	*start;
	const char	*end;
	size_t		len;
	char		buf[256];

	if (!response)
		return ;
	p = str_find_case(response, "Server:");
	if (!p)
		return ;
	p += 7;
	while (*p && isspace(*p))
		p++;
	start = p;
	end = start;
	while (*end && *end != '\r' && *end != '\n')
		end++;
	len = end - start;
	if (len > 0 && len < 200)
	{
		snprintf(buf, sizeof(buf), "IPP: %.*s", (int)len, start);
		strncpy(service_str, buf, SERVICE_LEN - 1);
	}
}

/*
** Parse SSH banner to extract version
** Format: SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u6
*/
static void	parse_ssh_banner(const char *banner, char *service_str)
{
	const char	*p;
	char		buf[128];
	size_t		len;

	if (!banner || !strstr(banner, "SSH"))
		return ;

	/* Find version part after "SSH-" */
	p = strstr(banner, "SSH-");
	if (p)
	{
		p += 4;  /* skip "SSH-" */
		/* Copy until newline or null */
		len = 0;
		while (p[len] && p[len] != '\r' && p[len] != '\n' && len < 100)
			len++;
		if (len > 0)
		{
			snprintf(buf, sizeof(buf), "SSH: %.*s", (int)len, p);
			strncpy(service_str, buf, SERVICE_LEN - 1);
		}
	}
}

/*
** Case-insensitive string comparison (portable version)
*/
static int	str_ncasecmp(const char *s1, const char *s2, size_t n)
{
	unsigned char	c1;
	unsigned char	c2;

	while (n > 0)
	{
		c1 = (unsigned char)tolower(*s1);
		c2 = (unsigned char)tolower(*s2);
		
		if (c1 != c2)
			return ((int)c1 - (int)c2);
		
		if (*s1 == '\0')
			return (0);
		
		s1++;
		s2++;
		n--;
	}
	return (0);
}

/*
** Case-insensitive string search (portable version)
*/
static const char	*str_find_case(const char *haystack, const char *needle)
{
	size_t	len;
	size_t	i;

	if (!haystack || !needle)
		return (NULL);
	
	len = strlen(needle);
	
	for (i = 0; haystack[i]; i++)
	{
		if (str_ncasecmp(&haystack[i], needle, len) == 0)
			return (&haystack[i]);
	}
	return (NULL);
}

/*
** Parse HTTP response to extract Server header
** Looks for "Server: ..." line
*/
static void	parse_http_response(const char *response, char *service_str)
{
	const char	*p;
	const char	*start;
	const char	*end;
	size_t		len;
	char		buf[256];

	if (!response)
		return ;

	/* Find "Server:" header (case-insensitive) */
	p = str_find_case(response, "Server:");
	if (p)
	{
		p += 7;  /* skip "Server:" */
		
		/* Skip whitespace */
		while (*p && isspace(*p))
			p++;
		
		start = p;
		/* Find end of line */
		end = start;
		while (*end && *end != '\r' && *end != '\n')
			end++;
		
		len = end - start;
		if (len > 0 && len < 200)
		{
			snprintf(buf, sizeof(buf), "HTTP: %.*s", (int)len, start);
			strncpy(service_str, buf, SERVICE_LEN - 1);
		}
	}
}

/*
** Parse FTP banner to extract version
** Format: 220 ProFTPD Server
*/
static void	parse_ftp_banner(const char *banner, char *service_str)
{
	const char	*p;
	size_t		len;
	char		buf[128];

	if (!banner)
		return ;

	/* Find first space after code */
	p = banner;
	if (p[0] >= '0' && p[0] <= '9')
	{
		p++;
		if (p[0] >= '0' && p[0] <= '9')
		{
			p++;
			if (p[0] >= '0' && p[0] <= '9')
				p++;
		}
		
		/* Skip space */
		while (*p && isspace(*p))
			p++;
		
		/* Copy rest of line */
		len = 0;
		while (p[len] && p[len] != '\r' && p[len] != '\n' && len < 100)
			len++;
		
		if (len > 0)
		{
			snprintf(buf, sizeof(buf), "FTP: %.*s", (int)len, p);
			strncpy(service_str, buf, SERVICE_LEN - 1);
		}
	}
}

/*
** Send probe and receive response with timeout
*/
static int	send_service_probe(struct in_addr addr, uint16_t port,
		const char *probe_data, size_t probe_len, char *response, size_t resp_size)
{
	int					sock;
	struct sockaddr_in	saddr;
	struct timeval		tv;
	fd_set				rfds;
	int					n;
	size_t				total;

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
		return (-1);

	/* Non-blocking connect setup */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = addr;
	saddr.sin_port = htons(port);

	/* Try to connect */
	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
	{
		close(sock);
		return (-1);
	}

	/* Send probe if provided */
	if (probe_data && probe_len > 0)
	{
		if (send(sock, probe_data, probe_len, 0) < 0)
		{
			close(sock);
			return (-1);
		}
	}

	/* Receive response with timeout */
	tv.tv_sec = SERVICE_PROBE_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

	total = 0;
	while (1)
	{
		if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0)
			break ;
		
		n = recv(sock, response + total, resp_size - total - 1, 0);
		if (n <= 0)
			break ;
		
		total += n;
		if (total >= resp_size - 1)
			break ;
	}

	response[total] = '\0';
	close(sock);
	return (total);
}

/*
** Resolve the registered service name for a port via the system's
** /etc/services database (getservbyport). Falls back to "unknown".
*/
static void	resolve_service_name(uint16_t port, char *service_str)
{
	struct servent	*se;

	se = getservbyport(htons(port), NULL);
	if (se && se->s_name)
		snprintf(service_str, SERVICE_LEN, "%s", se->s_name);
	else
		snprintf(service_str, SERVICE_LEN, "unknown");
}

/*
** Find probe for a given port
*/
static const t_probe	*find_probe(uint16_t port)
{
	int	i;

	i = 0;
	while (g_probes[i].name != NULL)
	{
		if (g_probes[i].port == port)
			return (&g_probes[i]);
		i++;
	}
	return (NULL);
}

/*
** Detect service on a specific port
** Called for each open port
*/
int	service_detect_port(struct in_addr addr, uint16_t port, char *service_str)
{
	const t_probe	*probe;
	char			response[SERVICE_BUFFER_SIZE];
	int				n;

	if (!service_str)
		return (-1);

	/* Resolve base service name from system /etc/services database */
	resolve_service_name(port, service_str);

	probe = find_probe(port);
	if (!probe)
		return (0);

	/* Send probe and get response for banner/version detection */
	n = send_service_probe(addr, port, probe->probe_data, probe->probe_len,
			response, sizeof(response));
	if (n <= 0)
		return (0);

	/* Parse response based on service */
	if (strcmp(probe->name, "ssh") == 0)
		parse_ssh_banner(response, service_str);
	else if (strcmp(probe->name, "http") == 0 || strcmp(probe->name, "https") == 0)
		parse_http_response(response, service_str);
	else if (strcmp(probe->name, "ftp") == 0)
		parse_ftp_banner(response, service_str);
	else if (strcmp(probe->name, "ipp") == 0)
		parse_ipp_response(response, service_str);
	else if (strcmp(probe->name, "rpcbind") == 0)
		; /* binary RPC reply confirms the service; name already set */
	else
	{
		/*
		** Fallback: use the first line of the response only when it is
		** entirely printable ASCII.  Binary responses (e.g. TLS greetings,
		** RPC framing) are silently ignored and the getservbyport name is
		** kept intact.
		*/
		size_t	len;
		size_t	k;
		char	*nl;
		int		printable;

		nl = strchr(response, '\n');
		if (!nl)
			nl = strchr(response, '\r');
		if (nl)
			len = (size_t)(nl - response);
		else
			len = strlen(response);
		printable = (len > 0 && len < 100);
		for (k = 0; printable && k < len; k++)
			if ((unsigned char)response[k] < 32 && response[k] != '\t')
				printable = 0;
		if (printable)
			snprintf(service_str, SERVICE_LEN, "%.*s", (int)len, response);
	}

	return (n);
}

/*
** Resolve service names for all open ports using getservbyport only.
** No network connections — always called after every scan.
*/
void	service_resolve_names(const t_options *opts, t_scan_result **results)
{
	size_t	h;
	int		port;
	int		scan_type;

	if (!opts || !results)
		return ;

	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (!results[h][port].port)
				continue ;
			for (scan_type = 0; scan_type < SCAN_MAX; scan_type++)
			{
				if (results[h][port].state[scan_type] == PORT_OPEN)
				{
					resolve_service_name((uint16_t)port,
						results[h][port].service.name);
					results[h][port].service.detected = true;
					break ;
				}
			}
		}
	}
}

/*
** Analyze services on all open ports
** Called after scan completes
*/
void	service_detect_analyze(const t_options *opts, t_scan_result **results)
{
	size_t	h;
	int		port;
	int		scan_type;

	if (!opts || !results)
		return ;

	for (h = 0; h < opts->ip_count; h++)
	{
		for (port = 1; port <= MAX_PORTS; port++)
		{
			if (!results[h][port].port)
				continue ;
			
			/* Check all scan types for open ports */
			for (scan_type = 0; scan_type < SCAN_MAX; scan_type++)
			{
				if (results[h][port].state[scan_type] == PORT_OPEN)
				{
					printf("Detecting service on %s:%d... ",
							opts->ips[h].input, port);
					fflush(stdout);
					
					service_detect_port(opts->ips[h].addr, port,
							results[h][port].service.name);
					
					if (results[h][port].service.name[0])
					{
						results[h][port].service.detected = true;
						printf("%s\n", results[h][port].service.name);
					}
					else
						printf("(no response)\n");
					
					break ;  /* One detection per port */
				}
			}
		}
	}
}
