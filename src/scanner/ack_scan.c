#include "scanner_internal.h"

/*
** ACK scan: send a lone ACK to probe firewall state. A RST back means the
** port is reachable (unfiltered); silence means a stateful filter swallowed
** the probe (filtered, via the no_reply_state pre-fill). It never reports
** open/closed — that is not what an ACK scan measures.
*/
int	ack_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t	buf[60];
	size_t	len;

	len = build_tcp_packet(buf, src, dst, sport, dport, SCAN_ACK);
	return (scan_send_raw(sock, buf, len, dst, dport));
}

t_port_state	ack_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_UNFILTERED);
	return (PORT_UNKNOWN);
}
