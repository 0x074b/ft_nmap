#include "scanner_internal.h"

/*
** SYN scan ("half-open"): send a lone SYN. A SYN/ACK back means the port is
** open; a RST means it is closed; silence means filtered (handled by the
** no_reply_state pre-fill in scan_stride).
*/
int	syn_send(const t_sender *s, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t		buf[MAX_PROBE_LEN];
	t_pkt_cfg	cfg;
	size_t		len;

	cfg = opts_to_pkt_cfg(s->opts);
	len = build_tcp_packet(buf, s->src, dst, sport, dport, SCAN_SYN, &cfg);
	return (scan_send_raw(s, buf, len, dst, dport));
}

t_port_state	syn_recv(const struct tcphdr *tcph)
{
	if (tcph->rst)
		return (PORT_CLOSED);
	if (tcph->syn && tcph->ack)
		return (PORT_OPEN);
	return (PORT_UNKNOWN);
}
