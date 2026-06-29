#include "scanner_internal.h"

/*
** NULL scan — NOT IMPLEMENTED YET (placeholder).
**
** A real NULL scan builds a TCP packet with no flags set at all. As with
** FIN/XMAS, a closed port answers RST and an open port stays silent, so the
** classifier should map RST -> closed with a no_reply_state of
** PORT_OPEN_FILTERED. Until then send is a no-op and recv returns no verdict.
*/
int	null_send(const t_sender *s, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t		buf[MAX_PROBE_LEN];
	t_pkt_cfg	cfg;
	size_t		len;

	cfg = opts_to_pkt_cfg(s->opts);
	len = build_tcp_packet(buf, s->src, dst, sport, dport, SCAN_NULL, &cfg);
	return (scan_send_raw(s, buf, len, dst, dport));
}

t_port_state	null_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	return (PORT_UNKNOWN);
}
