#ifndef SCANNER_INTERNAL_H
# define SCANNER_INTERNAL_H

# include "ft_nmap.h"

/*
** Per scan-type behaviour, looked up through scan_ops(). The generic
** orchestration in scan.c stays scan-type agnostic and drives everything
** through these three knobs:
**
**   - send():     emit one probe for this scan type to dst:dport.
**                 Takes the full t_sender so evasion options are reachable.
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
	int				(*send)(const t_sender *s, uint16_t sport,
						struct in_addr dst, uint16_t dport);
	t_port_state	(*classify)(const struct tcphdr *tcph);
	t_port_state	no_reply_state;
	const char		*name;
}	t_scan_ops;

const t_scan_ops	*scan_ops(t_scan_type type);

/*
** Shared raw-send helper: wrap an already-built packet and push it out.
** Handles fragmentation (-f) and AF_PACKET fake-MAC transparently.
*/
int				scan_send_raw(const t_sender *s, const uint8_t *buf, size_t len,
					struct in_addr dst, uint16_t dport);

/*
** Extract evasion settings from opts into a t_pkt_cfg for packet builders.
** Returns a zero-initialised cfg when opts is NULL (safe default).
*/
static inline t_pkt_cfg	opts_to_pkt_cfg(const t_options *opts)
{
	t_pkt_cfg	cfg;

	if (!opts)
		return ((t_pkt_cfg){0});
	cfg.ttl = opts->custom_ttl;
	cfg.random_window = opts->random_window;
	cfg.bad_checksum = opts->bad_checksum;
	cfg.data_length = opts->data_length;
	return (cfg);
}

/* per-type send / classify. */
int				syn_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	syn_recv(const struct tcphdr *tcph);

int				ack_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	ack_recv(const struct tcphdr *tcph);

int				fin_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	fin_recv(const struct tcphdr *tcph);

int				null_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	null_recv(const struct tcphdr *tcph);

int				xmas_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	xmas_recv(const struct tcphdr *tcph);

int				udp_send(const t_sender *s, uint16_t sport,
					struct in_addr dst, uint16_t dport);
t_port_state	udp_recv(const struct tcphdr *tcph);

#endif
