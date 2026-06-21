#include "scanner_internal.h"

/*
** XMAS scan — NOT IMPLEMENTED YET (placeholder).
**
** A real XMAS scan builds a TCP packet with the FIN, PSH and URG flags set
** (the packet is "lit up like a christmas tree"). Closed ports answer RST,
** open ports stay silent, so the classifier should map RST -> closed with a
** no_reply_state of PORT_OPEN_FILTERED. Until then send is a no-op and recv
** returns no verdict.
*/
int	xmas_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t	buf[60];
	size_t	len;

	len = build_tcp_packet(buf, src, dst, sport, dport, SCAN_XMAS);
	return (scan_send_raw(sock, buf, len, dst, dport));
}

t_port_state	xmas_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	return (PORT_UNKNOWN);
}
