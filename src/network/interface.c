#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "ft_nmap.h"

/*
** Discover a usable IPv4 source address from any up, non-loopback
** interface. The pcap handle itself listens on the "any" pseudo-interface
** so loopback traffic (e.g. scans against 127.0.0.1 or our own LAN IP)
** is captured too — it would otherwise miss reply packets that never
** traverse a physical NIC. Output buffers must hold IFACE_LEN and a
** struct in_addr.
*/
int	pick_interface(char *iface, struct in_addr *src)
{
	struct ifaddrs		*ifap;
	struct ifaddrs		*ifa;
	struct sockaddr_in	*sa;

	if (getifaddrs(&ifap) < 0)
	{
		perror("getifaddrs");
		return (-1);
	}
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue ;
		if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
			continue ;
		sa = (struct sockaddr_in *)ifa->ifa_addr;
		strncpy(iface, "any", IFACE_LEN - 1);
		iface[IFACE_LEN - 1] = '\0';
		*src = sa->sin_addr;
		freeifaddrs(ifap);
		return (0);
	}
	freeifaddrs(ifap);
	fprintf(stderr, "Error: no suitable interface found\n");
	return (-1);
}
