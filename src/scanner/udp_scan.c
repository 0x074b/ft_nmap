#include "scanner_internal.h"

int	udp_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t	buf[60];
	size_t	len;

	len = build_udp_packet(buf, src, dst, sport, dport, NULL, 0);
	return (scan_send_raw(sock, buf, len, dst, dport));
}

/* UDP scan uses ICMP and/or UDP replies, not the shared TCP classifier path. */
t_port_state	udp_recv(const struct tcphdr *tcph)
{
	(void)tcph;
	return (PORT_UNKNOWN);
}
