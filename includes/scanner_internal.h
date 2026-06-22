#ifndef SCANNER_INTERNAL_H
# define SCANNER_INTERNAL_H

# include "ft_nmap.h"

/*
** Per scan-type behaviour, looked up through scan_ops(). The generic
** orchestration in scan.c stays scan-type agnostic and drives everything
** through these three knobs:
**
**   - send():     emit one probe for this scan type to dst:dport.
**   - classify(): turn a matched TCP reply into a port state. Returning
**                 PORT_UNKNOWN means "no verdict" — the slot keeps the
**                 no_reply_state the stride pre-filled.
**   - no_reply_state: what a silent port resolves to for this scan type
**                 (e.g. SYN -> filtered, FIN -> open|filtered).
**
** name is used by the report for the per-scan-type column heading.
*/
typedef struct s_scan_ops
{
	int				(*send)(int sock, struct in_addr src, uint16_t sport,
						struct in_addr dst, uint16_t dport);
	t_port_state	(*classify)(const struct tcphdr *tcph);
	t_port_state	no_reply_state;
	const char		*name;
}	t_scan_ops;

const t_scan_ops	*scan_ops(t_scan_type type);

/*
** Shared raw-send helper: wrap an already-built packet in a sockaddr_in and
** push it out the raw socket. Returns 0 on success, -1 on sendto failure.
*/
int				scan_send_raw(int sock, const uint8_t *buf, size_t len,
					struct in_addr dst, uint16_t dport);

/* per-type send / classify. SYN and ACK are implemented; FIN, NULL, XMAS and
** UDP are placeholders wired into the dispatch table, ready to be filled in. */
int				syn_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	syn_recv(const struct tcphdr *tcph);

int				ack_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	ack_recv(const struct tcphdr *tcph);

int				fin_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	fin_recv(const struct tcphdr *tcph);

int				null_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	null_recv(const struct tcphdr *tcph);

int				xmas_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	xmas_recv(const struct tcphdr *tcph);

int				udp_send(int sock, struct in_addr src, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	udp_recv(const struct tcphdr *tcph);

#endif
