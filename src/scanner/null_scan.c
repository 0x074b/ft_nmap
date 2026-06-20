#include "scanner_internal.h"

/*
** NULL scan — NOT IMPLEMENTED YET (placeholder).
**
** A real NULL scan builds a TCP packet with no flags set at all. As with
** FIN/XMAS, a closed port answers RST and an open port stays silent, so the
** classifier should map RST -> closed with a no_reply_state of
** PORT_OPEN_FILTERED. Until then send is a no-op and recv returns no verdict.
*/
int	null_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	(void)sock;
	(void)src;
	(void)sport;
	(void)dst;
	(void)dport;
	return (0);
}

t_port_state	null_recv(const struct tcphdr *tcph)
{
	(void)tcph;
	return (PORT_UNKNOWN);
}
