#ifndef SCANNER_INTERNAL_H
# define SCANNER_INTERNAL_H

# include "ft_nmap.h"

int	tcp_scan_port_for_type(t_scan_type type, int sock, pcap_t *p,
		struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport,
		uint32_t timeout_ms,
		t_port_state *state);

#endif
