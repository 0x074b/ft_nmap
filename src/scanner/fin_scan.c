#include "scanner_internal.h"

/*
** FIN scan — NOT IMPLEMENTED YET (placeholder).
**
** A real FIN scan builds a TCP packet with only the FIN flag set and sends
** it. On most stacks a closed port answers with RST while an open port stays
** silent, so the classifier should map RST -> closed and rely on a
** no_reply_state of PORT_OPEN_FILTERED for silence. Until then send is a
** no-op and recv returns no verdict, so FIN ports report as unknown.
*/
int	fin_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t	buf[60];
	size_t	len;

	len = build_tcp_packet(buf, src, dst, sport, dport, SCAN_FIN);
	return (scan_send_raw(sock, buf, len, dst, dport));
}

t_port_state	fin_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	return (PORT_UNKNOWN);
}
