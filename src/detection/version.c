#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <unistd.h>

#include "ft_nmap.h"

/*
** Attempt to connect to the target on the given port and grab the service
** banner (greeting message). Works for services like HTTP, SSH, FTP, SMTP.
** Returns 0 on success, -1 on failure. Fills in svc->banner and sets detected.
*/
int	detect_service_version(struct in_addr target, uint16_t port,
		t_service *svc, uint32_t timeout_ms)
{
	int						sock;
	struct sockaddr_in		sa;
	fd_set					rfds;
	struct timeval			tv;
	int						flags;
	char					buf[BANNER_LEN];
	ssize_t					n;
	int						ret;

	memset(svc, 0, sizeof(*svc));
	svc->port = port;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return (-1);

	/* Set non-blocking mode */
	flags = 1;
	if (ioctl(sock, FIONBIO, &flags) < 0)
	{
		close(sock);
		return (-1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr = target;
	sa.sin_port = htons(port);

	ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0 && errno != EINPROGRESS)
	{
		close(sock);
		return (-1);
	}

	/* Wait for connection with timeout - use write set to check if connected */
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	ret = select(sock + 1, NULL, &rfds, NULL, &tv);
	if (ret <= 0)
	{
		close(sock);
		return (-1);
	}

	/* Try to read banner */
	memset(buf, 0, sizeof(buf));
	n = recv(sock, buf, sizeof(buf) - 1, MSG_DONTWAIT);
	close(sock);

	if (n > 0)
	{
		strncpy(svc->banner, buf, BANNER_LEN - 1);
		svc->detected = true;

		/* Heuristic: guess service name from banner */
		if (strstr(buf, "SSH"))
			strncpy(svc->name, "ssh", SERVICE_LEN - 1);
		else if (strstr(buf, "220"))
			strncpy(svc->name, "smtp", SERVICE_LEN - 1);
		else if (strstr(buf, "HTTP"))
			strncpy(svc->name, "http", SERVICE_LEN - 1);
		else if (strstr(buf, "FTP"))
			strncpy(svc->name, "ftp", SERVICE_LEN - 1);
		else
			strncpy(svc->name, "unknown", SERVICE_LEN - 1);
		return (0);
	}
	return (-1);
}
