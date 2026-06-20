#include "scanner_internal.h"

/*
** FIN scan — NOT IMPLEMENTED YET (placeholder).
**
** A real FIN scan builds a TCP packet with only the FIN flag set and sends
** it. On most stacks a closed port answers with RST while an open port stays
** silent, so the classifier should map RST -> closed and rely on a
** no_reply_state of PORT_OPEN_FILTERED for silence. Until then send is a
** no-op and recv returns no verdict, so FIN ports report as unknown.
*/
int	fin_send(int sock, struct in_addr src, uint16_t sport,
		struct in_addr dst, uint16_t dport)
{
	(void)sock;
	(void)src;
	(void)sport;
	(void)dst;
	(void)dport;
	return (0);
}

t_port_state	fin_recv(const struct tcphdr *tcph)
{
	(void)tcph;
	return (PORT_UNKNOWN);
}
