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
int	fin_send(const t_sender *s, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t		buf[MAX_PROBE_LEN];
	t_pkt_cfg	cfg;
	size_t		len;

	cfg = opts_to_pkt_cfg(s->opts);
	len = build_tcp_packet(buf, s->src, dst, sport, dport, SCAN_FIN, &cfg);
	return (scan_send_raw(s, buf, len, dst, dport));
}

t_port_state	fin_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	return (PORT_UNKNOWN);
}
