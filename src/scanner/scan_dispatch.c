#include "ft_nmap.h"

int	scan_port(t_scan_type type, int sock, pcap_t *p,
		struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport,
		uint32_t timeout_ms, t_port_state *state)
{
	if (type == SCAN_SYN)
		return (syn_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	if (type == SCAN_ACK)
		return (ack_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	if (type == SCAN_FIN)
		return (fin_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	if (type == SCAN_NULL)
		return (null_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	if (type == SCAN_XMAS)
		return (xmas_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	if (type == SCAN_UDP)
		return (udp_scan_port(sock, p, src, sport, dst, dport, timeout_ms, state));
	return (-1);
}
