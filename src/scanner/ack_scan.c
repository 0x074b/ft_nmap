#include "scanner_internal.h"

int	ack_scan_port(int sock, pcap_t *p,
		struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport,
		uint32_t timeout_ms, t_port_state *state)
{
	return (tcp_scan_port_for_type(SCAN_ACK, sock, p, src, sport,
			dst, dport, timeout_ms, state));
}
