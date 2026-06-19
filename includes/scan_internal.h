#ifndef SCAN_INTERNAL_H
# define SCAN_INTERNAL_H

# include "ft_nmap.h"

int	tcp_scan_with_flags(int sock, pcap_t *p,
			struct in_addr src, uint16_t sport,
			struct in_addr dst, uint16_t dport,
			uint32_t timeout_ms, uint8_t flags,
			t_scan_type scan_type, t_port_state *state);

#endif
