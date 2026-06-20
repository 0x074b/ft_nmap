#include "scanner_internal.h"

/*
** UDP scan — NOT IMPLEMENTED YET (placeholder).
**
** Unlike the TCP scans this one does not fit the shared TCP path: a real
** implementation sends a UDP datagram to dst:dport and watches for an ICMP
** port-unreachable (type 3, code 3 -> closed; other type 3 codes ->
** filtered) or a UDP answer (-> open), defaulting silence to open|filtered.
** That needs a UDP probe builder and ICMP capture, so recv's tcphdr argument
** is a stand-in only. Until then send is a no-op and recv returns no verdict.
*/
int	udp_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	(void)sock;
	(void)src;
	(void)sport;
	(void)dst;
	(void)dport;
	return (0);
}

t_port_state	udp_recv(const struct tcphdr *tcph)
{
	(void)tcph;
	return (PORT_UNKNOWN);
}
