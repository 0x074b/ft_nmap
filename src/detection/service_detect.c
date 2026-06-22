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

#include "ft_nmap.h"

#define SERVICE_PROBE_TIMEOUT 2
#define SERVICE_BUFFER_SIZE 4096
#define MAX_PROBES_PER_PORT 5

/*
** Enhanced probe table with multiple probes per port
** Real service detection: try multiple approaches
*/
typedef struct s_probe_sequence
{
	uint16_t	port;
	const char	*name;
	const char	*primary_probe;
	size_t		primary_len;
	const char	*fallback_probe;
	size_t		fallback_len;
	bool		expect_banner_first;  /* does service send banner without probe? */
}	t_probe_sequence;

/* Service probe database - enhanced */
static const t_probe_sequence	g_probe_sequences[] = {
	{
		21,
		"ftp",
		"USER anonymous\r\nPASS test@test.com\r\n",
		37,
		"",
		0,
		true  /* FTP sends 220 banner first */
	},
	{
		22,
		"ssh",
		"SSH-2.0-OpenSSH_Scanner\r\n",
		25,
		"",
		0,
		true  /* SSH sends banner first */
	},
	{
		25,
		"smtp",
		"EHLO scanner\r\n",
		14,
		"HELO scanner\r\n",
		14,
		true  /* SMTP sends 220 first */
	},
	{
		53,
		"dns",
		"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
		29,
		"",
		0,
		false
	},
	{
		80,
		"http",
		"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
		38,
		"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n",
		38,
		false
	},
	{
		110,
		"pop3",
		"USER anonymous\r\n",
		16,
		"",
		0,
		true  /* POP3 sends +OK first */
	},
	{
		143,
		"imap",
		"A1 CAPABILITY\r\n",
		15,
		"",
		0,
		true  /* IMAP sends * OK first */
	},
	{
		443,
		"https",
		"GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
		38,
		"",
		0,
		false  /* TLS handshake */
	},
	{
		3306,
		"mysql",
		"",
		0,
		"",
		0,
		true  /* MySQL sends greeting first */
	},
	{
		5432,
		"postgresql",
		"",
		0,
		"",
		0,
		true  /* PostgreSQL sends greeting first */
	},
	{
		5900,
		"vnc",
		"",
		0,
		"",
		0,
		true  /* VNC sends RFB greeting */
	},
	{
		3389,
		"rdp",
		"",
		0,
		"",
		0,
		true  /* RDP sends greeting */
	},
	{
		0,
		NULL,
		NULL,
		0,
		NULL,
		0,
		false
	}
};

/*
** Service signature database
** Maps service + response patterns to specific versions
*/
typedef struct s_service_sig
{
	const char	*service;
	const char	*pattern;
	const char	*version;
	int			confidence;  /* 0-100 */
}	t_service_sig;

static const t_service_sig	g_service_sigs[] = {
	/* SSH signatures */
	{"ssh", "OpenSSH_7.4", "OpenSSH 7.4", 95},
	{"ssh", "OpenSSH_7.6", "OpenSSH 7.6", 95},
	{"ssh", "OpenSSH_8.0", "OpenSSH 8.0", 95},
	{"ssh", "OpenSSH_8.2", "OpenSSH 8.2", 95},
	{"ssh", "OpenSSH_8.9", "OpenSSH 8.9", 95},
	{"ssh", "OpenSSH", "OpenSSH (unknown version)", 70},
	
	/* HTTP/Apache */
	{"http", "Apache/2.4.41", "Apache 2.4.41", 95},
	{"http", "Apache/2.4.51", "Apache 2.4.51", 95},
	{"http", "Apache/2.2", "Apache 2.2.x", 90},
	{"http", "Apache", "Apache (unknown version)", 75},
	
	/* Nginx */
	{"http", "nginx/1.18", "Nginx 1.18.0", 95},
	{"http", "nginx/1.20", "Nginx 1.20.0", 95},
	{"http", "nginx/1.24", "Nginx 1.24.0", 95},
	{"http", "nginx", "Nginx (unknown version)", 75},
	
	/* Microsoft IIS */
	{"http", "Microsoft-IIS/10.0", "IIS 10.0", 95},
	{"http", "Microsoft-IIS/8.5", "IIS 8.5", 95},
	{"http", "Microsoft-IIS", "IIS (unknown version)", 75},
	
	/* HTTPS (same servers, just over TLS) */
	{"https", "Apache/2.4.41", "Apache 2.4.41 (TLS)", 95},
	{"https", "Apache/2.4.51", "Apache 2.4.51 (TLS)", 95},
	{"https", "nginx/1.18", "Nginx 1.18.0 (TLS)", 95},
	{"https", "nginx/1.20", "Nginx 1.20.0 (TLS)", 95},
	{"https", "Microsoft-IIS", "IIS (TLS)", 90},
	
	/* FTP */
	{"ftp", "ProFTPD 1.3", "ProFTPD 1.3.x", 90},
	{"ftp", "vsftpd 2", "vsftpd 2.x", 90},
	{"ftp", "vsftpd 3", "vsftpd 3.x", 90},
	{"ftp", "Pure-FTPd", "Pure-FTPd", 85},
	
	/* SMTP */
	{"smtp", "Postfix", "Postfix", 85},
	{"smtp", "Sendmail", "Sendmail", 85},
	{"smtp", "Exim", "Exim", 85},
	
	/* MySQL */
	{"mysql", "MySQL 5.7", "MySQL 5.7", 90},
	{"mysql", "MySQL 8.0", "MySQL 8.0", 90},
	{"mysql", "MySQL", "MySQL", 70},
	{"mysql", "MariaDB", "MariaDB", 85},
	
	/* PostgreSQL */
	{"postgresql", "PostgreSQL 9.6", "PostgreSQL 9.6", 90},
	{"postgresql", "PostgreSQL 10", "PostgreSQL 10", 90},
	{"postgresql", "PostgreSQL 12", "PostgreSQL 12", 90},
	{"postgresql", "PostgreSQL 13", "PostgreSQL 13", 90},
	{"postgresql", "PostgreSQL", "PostgreSQL", 70},
	
	/* Sentinel */
	{NULL, NULL, NULL, 0}
};

/*
** Detect TLS/SSL by looking for binary TLS record markers
** If HTTP GET returns binary data starting with 0x16 0x03 = TLS
** Returns true if TLS detected, false if plain HTTP or error
*/
static bool	detect_tls_by_response(const unsigned char *response, size_t len)
{
	if (!response || len < 5)
		return (false);

	/* TLS record types: 0x16=Handshake, 0x17=Application, 0x14=Change, 0x15=Alert */
	/* Check for TLS ServerHello (0x16 0x03 0x01/0x03) */
	if (response[0] == 0x16 && response[1] == 0x03 &&
		(response[2] == 0x01 || response[2] == 0x03))
		return (true);

	/* Check for TLS Alert (0x15 0x03) */
	if (response[0] == 0x15 && response[1] == 0x03)
		return (true);

	return (false);
}

/*
** Detect service from response heuristics
*/
static const char	*detect_service_type(const char *response, size_t len)
{
	if (!response || len == 0)
		return (NULL);

	/* Check for TLS binary first (before HTTP text patterns) */
	if (detect_tls_by_response((unsigned char *)response, len))
		return ("https");

	/* Check for HTTP */
	if (strstr(response, "HTTP/") || strstr(response, "Server:"))
		return ("http");
	
	/* Check for SSH */
	if (strncmp(response, "SSH-", 4) == 0)
		return ("ssh");
	
	/* Check for FTP */
	if (response[0] >= '2' && response[0] <= '5' && 
		isdigit(response[1]) && isdigit(response[2]) && response[3] == ' ')
		return ("ftp");
	
	/* Check for SMTP */
	if (strncmp(response, "220", 3) == 0)
		return ("smtp");
	
	/* Check for POP3 */
	if (strncmp(response, "+OK", 3) == 0)
		return ("pop3");
	
	/* Check for IMAP */
	if (strstr(response, "* OK"))
		return ("imap");
	
	/* Check for MySQL */
	if (len > 6 && response[4] == '\x00' && response[5] == '\x00' && response[6] == '\x00')
		return ("mysql");
	
	/* Check for PostgreSQL */
	if (strstr(response, "NOTICE:") || strstr(response, "FATAL:"))
		return ("postgresql");
	
	/* Check for VNC */
	if (strncmp(response, "RFB", 3) == 0)
		return ("vnc");
	
	return (NULL);
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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr = addr;
	saddr.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
	{
		close(sock);
		return (-1);
	}

	/* For banner-first services, wait for response first */
	tv.tv_sec = SERVICE_PROBE_TIMEOUT;
	tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);

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
	total = 0;
	while (1)
	{
		tv.tv_sec = SERVICE_PROBE_TIMEOUT;
		tv.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		
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
** Match response against signature database
*/
static const char	*match_signature(const char *service, const char *response)
{
	int	i;

	if (!service || !response)
		return (NULL);

	i = 0;
	while (g_service_sigs[i].service != NULL)
	{
		if (strcmp(g_service_sigs[i].service, service) == 0 &&
			strstr(response, g_service_sigs[i].pattern) != NULL)
		{
			return (g_service_sigs[i].version);
		}
		i++;
	}
	return (NULL);
}

/*
** Find probe sequence for port
*/
static const t_probe_sequence	*find_probe_sequence(uint16_t port)
{
	int	i;

	i = 0;
	while (g_probe_sequences[i].name != NULL)
	{
		if (g_probe_sequences[i].port == port)
			return (&g_probe_sequences[i]);
		i++;
	}
	return (NULL);
}

/*
** Detect service on a specific port
** Uses multi-probe approach and heuristics
*/
int	service_detect_port(struct in_addr addr, uint16_t port, char *service_str)
{
	const t_probe_sequence	*seq;
	char					response[SERVICE_BUFFER_SIZE];
	int						n;
	const char				*detected_service;
	const char				*version;

	if (!service_str)
		return (-1);

	service_str[0] = '\0';
	seq = find_probe_sequence(port);

	if (!seq)
		return (-1);

	/* Try primary probe */
	n = send_service_probe(addr, port, seq->primary_probe, seq->primary_len,
			response, sizeof(response));

	/* If no response, try fallback probe */
	if (n <= 0 && seq->fallback_probe && seq->fallback_len > 0)
	{
		n = send_service_probe(addr, port, seq->fallback_probe, seq->fallback_len,
				response, sizeof(response));
	}

	if (n <= 0)
		return (-1);

	/* Auto-detect service type from response (includes TLS detection) */
	detected_service = detect_service_type(response, n);

	if (detected_service)
	{
		/* Look up version in signature database */
		version = match_signature(detected_service, response);
		if (version)
			snprintf(service_str, SERVICE_LEN, "%s: %s", detected_service, version);
		else
		{
			/* Extract banner line */
			char	*nl;
			size_t	len;

			nl = strchr(response, '\n');
			if (!nl)
				nl = strchr(response, '\r');
			if (nl)
				len = nl - response;
			else
				len = strlen(response);

			if (len > 0 && len < 150)
				snprintf(service_str, SERVICE_LEN, "%s: %.*s",
						detected_service, (int)len, response);
			else
				snprintf(service_str, SERVICE_LEN, "%s", detected_service);
		}
	}

	return (n);
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
