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

#define SERVICE_PROBE_TIMEOUT	2
#define SERVICE_BUFFER_SIZE		4096

static const char	g_http_probe[] =
	"GET / HTTP/1.0\r\nHost: probe\r\nConnection: close\r\n\r\n";

/*
** RPC NULL call: record-mark framing + XID + CALL + rpcvers 2 +
** prog 100000 (portmap) + vers 2 + proc 0 (NULL) + AUTH_NULL x2.
*/
static const char	g_rpc_probe[44] = {
	'\x80', '\x00', '\x00', '\x28',
	'\x72', '\xfe', '\x1d', '\x13',
	'\x00', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x02',
	'\x00', '\x01', '\x86', '\xa0',
	'\x00', '\x00', '\x00', '\x02',
	'\x00', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00'
};

/* ------------------------------------------------------------------ */
/* String utilities                                                    */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Protocol-specific parsers (defined before use)                     */
/* ------------------------------------------------------------------ */

static void	parse_ssh_banner(const char *banner, char *service_str)
{
	const char	*p;
	char		buf[128];
	size_t		len;

	p = strstr(banner, "SSH-");
	if (!p)
		return ;
	p += 4;
	len = 0;
	while (p[len] && p[len] != '\r' && p[len] != '\n' && len < 100)
		len++;
	if (len > 0)
	{
		snprintf(buf, sizeof(buf), "SSH: %.*s", (int)len, p);
		strncpy(service_str, buf, SERVICE_LEN - 1);
	}
}

static void	parse_http_banner(const char *resp, char *service_str)
{
	const char	*p;
	const char	*start;
	const char	*end;
	size_t		len;
	char		buf[256];

	p = str_find_case(resp, "Server:");
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
		snprintf(buf, sizeof(buf), "HTTP: %.*s", (int)len, start);
		strncpy(service_str, buf, SERVICE_LEN - 1);
	}
}

/*
** Extract the first printable line from a text greeting
** (FTP 220, SMTP 220, POP3 +OK, IMAP * OK, …)
*/
static void	parse_text_greeting(const char *r, char *service_str)
{
	size_t	len;

	len = 0;
	while (r[len] && r[len] != '\r' && r[len] != '\n'
		&& len < (size_t)(SERVICE_LEN - 1))
	{
		if ((unsigned char)r[len] < 32 && r[len] != '\t')
		{
			len = 0;
			break ;
		}
		len++;
	}
	if (len > 0)
		snprintf(service_str, SERVICE_LEN, "%.*s", (int)len, r);
}

/* ------------------------------------------------------------------ */
/* Generic dispatcher: identifies protocol from response content      */
/* ------------------------------------------------------------------ */

static void	parse_any_banner(const char *r, int n, char *service_str)
{
	(void)n;

	if (!r || !r[0])
		return ;
	/* TLS/SSL handshake record — don't corrupt the service name */
	if ((unsigned char)r[0] == 0x16 && (unsigned char)r[1] == 0x03)
		return ;
	/* Binary protocol (RPC, etc.): high-bit first byte */
	if ((unsigned char)r[0] > 0x7f)
		return ;
	if (strncmp(r, "SSH-", 4) == 0)
	{
		parse_ssh_banner(r, service_str);
		return ;
	}
	if (strncmp(r, "HTTP/", 5) == 0 || str_find_case(r, "Server:") != NULL)
	{
		parse_http_banner(r, service_str);
		return ;
	}
	/* Generic text greeting */
	parse_text_greeting(r, service_str);
}

/* ------------------------------------------------------------------ */
/* TCP probe sender                                                    */
/* ------------------------------------------------------------------ */

static int	send_service_probe(struct in_addr addr, uint16_t port,
		const char *probe_data, size_t probe_len,
		char *response, size_t resp_size)
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
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = addr;
	saddr.sin_port = htons(port);
	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
	{
		close(sock);
		return (-1);
	}
	if (probe_data && probe_len > 0)
	{
		if (send(sock, probe_data, probe_len, 0) < 0)
		{
			close(sock);
			return (-1);
		}
	}
	tv.tv_sec = SERVICE_PROBE_TIMEOUT;
	tv.tv_usec = 0;
	total = 0;
	while (1)
	{
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		if (select(sock + 1, &rfds, NULL, NULL, &tv) <= 0)
			break ;
		n = recv(sock, response + total, resp_size - total - 1, 0);
		if (n <= 0)
			break ;
		total += (size_t)n;
		if (total >= resp_size - 1)
			break ;
	}
	response[total] = '\0';
	close(sock);
	return ((int)total);
}

/* ------------------------------------------------------------------ */
/* Service name lookup                                                 */
/* ------------------------------------------------------------------ */

static void	resolve_service_name(uint16_t port, char *service_str)
{
	struct servent	*se;

	se = getservbyport(htons(port), NULL);
	if (se && se->s_name)
		snprintf(service_str, SERVICE_LEN, "%s", se->s_name);
	else
		snprintf(service_str, SERVICE_LEN, "-");
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

/*
** Probe a single open port for version information.
** Content-based two-probe strategy (no hardcoded port table):
**   1. Banner grab (connect + wait)  — SSH, FTP, SMTP, POP3, IMAP …
**   2. HTTP GET                      — web servers on any port
**   3. RPC NULL call                 — port 111 specifically
** Protocol is detected from response content, not the port number.
*/
int	service_detect_port(struct in_addr addr, uint16_t port, char *service_str)
{
	char	response[SERVICE_BUFFER_SIZE];
	int		n;

	if (!service_str)
		return (-1);
	resolve_service_name(port, service_str);
	n = send_service_probe(addr, port, NULL, 0, response, sizeof(response));
	if (n > 0)
	{
		parse_any_banner(response, n, service_str);
		return (n);
	}
	n = send_service_probe(addr, port,
			g_http_probe, sizeof(g_http_probe) - 1,
			response, sizeof(response));
	if (n > 0)
	{
		parse_any_banner(response, n, service_str);
		return (n);
	}
	if (port == 111)
	{
		n = send_service_probe(addr, port,
				g_rpc_probe, sizeof(g_rpc_probe),
				response, sizeof(response));
		if (n > 0)
			return (n);
	}
	return (0);
}

/*
** Resolve service names for all open ports via getservbyport.
** No network — always called after every scan.
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
** Banner-probe all open ports.  Only called with -sV.
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
			for (scan_type = 0; scan_type < SCAN_MAX; scan_type++)
			{
				if (results[h][port].state[scan_type] == PORT_OPEN)
				{
					printf("Detecting service on %s:%d... ",
							opts->ips[h].input, port);
					fflush(stdout);
					service_detect_port(opts->ips[h].addr, (uint16_t)port,
							results[h][port].service.name);
					if (results[h][port].service.name[0])
					{
						results[h][port].service.detected = true;
						printf("%s\n", results[h][port].service.name);
					}
					else
						printf("(no response)\n");
					break ;
				}
			}
		}
	}
}

