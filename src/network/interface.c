#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "ft_nmap.h"

/*
** Discover a usable IPv4 source address from any up, non-loopback interface.
** The pcap handle always listens on the "any" pseudo-interface (so loopback
** and local replies are captured too), so the interface name is a constant and
** not returned here; we only need the source IP we stamp into outgoing packets
** and their TCP/UDP checksums. Output buffer must hold a struct in_addr.
*/
int	get_source_ip(struct in_addr *src)
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
		*src = sa->sin_addr;
		freeifaddrs(ifap);
		return (0);
	}
	freeifaddrs(ifap);
	fprintf(stderr, "Error: no suitable interface found\n");
	return (-1);
}
