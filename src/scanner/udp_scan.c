#include "scanner_internal.h"

int	udp_send(const t_sender *s, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	uint8_t		buf[MAX_PROBE_LEN];
	t_pkt_cfg	cfg;
	size_t		len;

	cfg = opts_to_pkt_cfg(s->opts);
	len = build_udp_packet(buf, s->src, dst, sport, dport, NULL, 0, &cfg);
	return (scan_send_raw(s, buf, len, dst, dport));
}

/* UDP scan uses ICMP and/or UDP replies, not the shared TCP classifier path. */
t_port_state	udp_recv(const struct tcphdr *tcph)
{
	(void)tcph;
	return (PORT_UNKNOWN);
}
