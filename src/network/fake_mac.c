#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ft_nmap.h"

/*
** Read /proc/net/route to find the default gateway for the given interface.
** The Gateway column is a 32-bit value stored in the native byte order of the
** kernel, which on Linux equals network byte order for in_addr.s_addr.
** Returns 0 and fills *gw on success, -1 if no default route is found.
*/
static int	get_default_gateway(const char *iface, struct in_addr *gw)
{
	FILE		*f;
	char		line[256];
	char		iface_col[64];
	unsigned int	dest;
	unsigned int	gw_hex;
	unsigned int	flags;

	f = fopen("/proc/net/route", "r");
	if (!f)
		return (-1);
	if (!fgets(line, sizeof(line), f))
		return (fclose(f), -1);
	while (fgets(line, sizeof(line), f))
	{
		if (sscanf(line, "%63s %x %x %x",
				iface_col, &dest, &gw_hex, &flags) != 4)
			continue ;
		/* Default route: Destination=0, flag RTF_UP|RTF_GATEWAY */
		if (dest == 0 && (flags & 0x0003)
			&& strcmp(iface_col, iface) == 0)
		{
			gw->s_addr = gw_hex;
			fclose(f);
			return (0);
		}
	}
	fclose(f);
	return (-1);
}

/*
** Look up the MAC address for a given IP on the given interface using
** SIOCGARP. Returns 0 and fills mac[6] on success, -1 on failure (entry
** incomplete or not found).
*/
static int	get_arp_mac(const char *iface, struct in_addr ip, uint8_t *mac)
{
	int				sock;
	struct arpreq	req;
	struct sockaddr_in	*pa;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return (-1);
	memset(&req, 0, sizeof(req));
	pa = (struct sockaddr_in *)&req.arp_pa;
	pa->sin_family = AF_INET;
	pa->sin_addr = ip;
	strncpy(req.arp_dev, iface, sizeof(req.arp_dev) - 1);
	if (ioctl(sock, SIOCGARP, &req) < 0)
		return (close(sock), -1);
	close(sock);
	if (!(req.arp_flags & ATF_COM))
		return (-1);
	memcpy(mac, req.arp_ha.sa_data, 6);
	return (0);
}

/*
** Send a tiny UDP datagram to the gateway to trigger an ARP exchange, then
** wait briefly for the kernel ARP cache to populate.
*/
static void	trigger_arp(struct in_addr gw)
{
	int				sock;
	struct sockaddr_in	sa;
	char			buf[1];

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		return ;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr = gw;
	sa.sin_port = htons(9);
	buf[0] = 0;
	sendto(sock, buf, 1, 0, (struct sockaddr *)&sa, sizeof(sa));
	close(sock);
	usleep(200000);
}

/*
** Initialise the AF_PACKET socket and resolve the gateway MAC address so
** probes can be sent with a spoofed source MAC (--fake-mac).
**
** On success: *l2_sock holds an open AF_PACKET socket, *gw_mac holds the
** gateway's MAC, *ifindex holds the interface index. Returns 0.
** On failure: *l2_sock is set to -1 and -1 is returned.
*/
int	fake_mac_init(const char *iface, const t_options *opts,
		int *l2_sock, uint8_t *gw_mac, int *ifindex)
{
	struct in_addr	gw;

	(void)opts;
	*l2_sock = socket(AF_PACKET, SOCK_RAW, htons(0x0800));
	if (*l2_sock < 0)
	{
		fprintf(stderr, "Warning: --fake-mac: AF_PACKET socket failed: %s\n",
			strerror(errno));
		return (-1);
	}
	printf("DEBUG iface=%s ifindex=%d\n", iface, *ifindex);
	*ifindex = (int)if_nametoindex(iface);
	if (!*ifindex)
	{
		fprintf(stderr, "Warning: --fake-mac: if_nametoindex(%s) failed\n",
			iface);
		printf("DEBUG iface=%s ifindex=%d\n", iface, *ifindex);
		close(*l2_sock);
		*l2_sock = -1;
		return (-1);
	}
	if (get_default_gateway(iface, &gw) < 0)
	{
		fprintf(stderr,
			"Warning: --fake-mac: cannot find default gateway, "
			"packets may not route\n");
		memset(gw_mac, 0, 6);
		return (0);
	}
	if (get_arp_mac(iface, gw, gw_mac) < 0)
	{
		trigger_arp(gw);
		if (get_arp_mac(iface, gw, gw_mac) < 0)
		{
			fprintf(stderr,
				"Warning: --fake-mac: cannot resolve gateway MAC, "
				"packets may not route\n");
			memset(gw_mac, 0, 6);
		}
	}
	return (0);
}
