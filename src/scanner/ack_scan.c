#include "scanner_internal.h"

/*
** ACK scan: send a lone ACK to probe firewall state. A RST back means the
** port is reachable (unfiltered); silence means a stateful filter swallowed
** the probe (filtered, via the no_reply_state pre-fill). It never reports
** open/closed — that is not what an ACK scan measures.
*/
int	ack_send(const t_sender *s, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t		buf[MAX_PROBE_LEN];
	t_pkt_cfg	cfg;
	size_t		len;

	cfg = opts_to_pkt_cfg(s->opts);
	len = build_tcp_packet(buf, s->src, dst, sport, dport, SCAN_ACK, &cfg);
	return (scan_send_raw(s, buf, len, dst, dport));
}

t_port_state	ack_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_UNFILTERED);
	return (PORT_UNKNOWN);
}
