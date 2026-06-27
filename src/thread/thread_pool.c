#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ft_nmap.h"

/*
** Sending and receiving are split. n = speedup + 1 sender threads stride the
** flattened host * port work space (see sender_main) and only transmit; a
** single receiver thread (receiver_main) owns the one capture handle and is the
** sole writer of results, so there is no locking. The receiver is pinned to its
** own core and the senders to the others, so 250 senders can never starve the
** drain — the cause of the ring drops the old per-worker-handle design hit.
*/

/* Returns true if sport is already assigned to an earlier scan type. */
static int	sport_taken(const uint16_t *sports, int upto, uint16_t sport)
{
	int	t;

	t = 0;
	while (t < upto)
	{
		if (sports[t] == sport)
			return (1);
		t++;
	}
	return (0);
}

/*
** One source port per selected scan type (shared by every sender and the
** receiver). A reply's destination port is one of these, which is how the
** receiver tells, e.g., a SYN-scan RST from an ACK-scan RST. Only the ~6 types
** need distinct ports now — not every worker — so the space is tiny.
*/
static void	assign_sports(uint16_t *sports, const t_options *opts)
{
	int			t;
	uint16_t	sport;

	t = 0;
	while (t < SCAN_MAX)
	{
		sports[t] = 0;
		if (opts->scan[t])
		{
			do {
				sport = (uint16_t)(49152 + (rand() % 16000));
			} while (sport_taken(sports, t, sport));
			sports[t] = sport;
		}
		t++;
	}
}

/* Compact the selected scan types' source ports for the BPF filter. */
static int	compact_sports(const uint16_t *sports, const t_options *opts,
		uint16_t *out)
{
	int	t;
	int	count;

	count = 0;
	t = 0;
	while (t < SCAN_MAX)
	{
		if (opts->scan[t])
			out[count++] = sports[t];
		t++;
	}
	return (count);
}

/*
** Flatten the selected ports (a sparse bool array) into a compact list of port
** numbers and return how many there are. Senders stride the combined
** host * port work space, so they need the active ports as a dense array.
*/
static int	collect_active_ports(const t_options *opts, uint16_t *out)
{
	int	port;
	int	n;

	n = 0;
	port = 1;
	while (port <= MAX_PORTS)
	{
		if (opts->ports[port])
			out[n++] = (uint16_t)port;
		port++;
	}
	return (n);
}

/* Pin a thread to one CPU core; core < 0 leaves it unpinned. */
static void	pin_tid(pthread_t tid, int core)
{
	cpu_set_t	set;

	if (core < 0)
		return ;
	CPU_ZERO(&set);
	CPU_SET(core, &set);
	pthread_setaffinity_np(tid, sizeof(set), &set);
}

/*
** Spawn the sender threads and pin them to the cores the receiver does not use
** (core 0 is reserved for the receiver when more than one core exists).
*/
static void	start_senders(t_sender *senders, pthread_t *tids, int n,
		int ncores)
{
	int	i;

	i = 0;
	while (i < n)
	{
		pthread_create(&tids[i], NULL, sender_main, &senders[i]);
		if (ncores > 1)
			pin_tid(tids[i], 1 + (i % (ncores - 1)));
		i++;
	}
}

static void	init_senders(t_sender *senders, int n, t_sender shared)
{
	int	i;

	i = 0;
	while (i < n)
	{
		senders[i] = shared;
		senders[i].id = i;
		senders[i].nsenders = n;
		i++;
	}
}

/*
** Run the whole scan: prefill the "no answer" defaults, open one capture
** handle, start the receiver on its own core, fan the host * port work out
** across n = speedup + 1 sender threads, then — once they have all finished —
** tell the receiver to drain its grace window and wind down. active_ports and
** sports live on this stack frame, which outlives every thread (we join before
** returning), so the shared pointers into them are safe.
*/
int	run_scan(const t_options *opts, int sock, const char *iface,
		struct in_addr src, t_scan_result **results, t_pcap_stats *stats)
{
	t_sender		*senders;
	pthread_t		*tids;
	pthread_t		recv_tid;
	uint16_t		active_ports[MAX_PORTS];
	uint16_t		sports[SCAN_MAX];
	uint16_t		filter_sports[SCAN_MAX];
	t_sender		shared;
	t_receiver		rctx;
	volatile int	senders_done;
	int				n;
	int				i;
	int				ncores;
	int				filter_count;

	n = opts->speedup + 1;
	senders = calloc(n, sizeof(*senders));
	tids = calloc(n, sizeof(*tids));
	if (!senders || !tids)
		return (free(senders), free(tids), -1);
	assign_sports(sports, opts);
	memset(&shared, 0, sizeof(shared));
	shared.sock = sock;
	shared.src = src;
	shared.opts = opts;
	shared.sports = sports;
	shared.active_ports = active_ports;
	shared.nports = collect_active_ports(opts, active_ports);
	prefill_results(opts, results, active_ports, shared.nports);
	filter_count = compact_sports(sports, opts, filter_sports);
	rctx.p = pcap_open_for_scan(iface, filter_sports, filter_count,
			opts->scan[SCAN_UDP] ? 1 : 0);
	if (!rctx.p)
		return (free(senders), free(tids), -1);
	senders_done = 0;
	rctx.opts = opts;
	rctx.sports = sports;
	rctx.results = results;
	rctx.senders_done = &senders_done;
/	pthread_create(&recv_tid, NULL, receiver_main, &rctx);
	pin_tid(recv_tid, ncores > 1 ? 0 : -1);
	init_senders(senders, n, shared);
	start_senders(senders, tids, n, ncores);
	for (i = 0; i < n; i++)
		pthread_join(tids[i], NULL);
	senders_done = 1;
	pthread_join(recv_tid, NULL);
	for (i = 0; i < n; i++)
		stats->send_fail += senders[i].send_fail;
	accumulate_pcap_stats(rctx.p, stats);
	pcap_close(rctx.p);
	return (free(senders), free(tids), 0);
}
