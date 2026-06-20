#include "scanner_internal.h"

/*
** SYN scan ("half-open"): send a lone SYN. A SYN/ACK back means the port is
** open; a RST means it is closed; silence means filtered (handled by the
** no_reply_state pre-fill in scan_stride).
*/
int	syn_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t	buf[60];
	size_t	len;

	len = build_syn_packet(buf, src, dst, sport, dport);
	return (scan_send_raw(sock, buf, len, dst, dport));
}

t_port_state	syn_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	if (tcph->syn && tcph->ack)
		return (PORT_OPEN);
	return (PORT_UNKNOWN);
}
