#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_nmap.h"

/*
** Each worker owns a stride of the flattened host * port work space (see
** worker_main): worker id handles every work unit u where u % nthreads == id,
** sending every selected scan type for that (host, port). Because each
** (host, port) pair belongs to exactly one worker, the shared results table is
** still partitioned with no overlapping writes — no lock needed — and replies
** route back to their sender via that worker's unique source port. The
** per-worker pass lives in worker_main (src/scanner/scan.c, the pthread start
** routine); run_scan below just hands out the work and threads.
*/

/*
** Returns true if sport is already used by any worker for any scan type.
** Unassigned slots are 0 (calloc) and never collide with a real sport.
*/
static int	sport_taken(uint16_t sport, t_worker *workers, int n)
{
	int	i;
	int	t;

	i = 0;
	while (i < n)
	{
		t = 0;
		while (t < SCAN_MAX)
		{
			if (workers[i].sport[t] == sport)
				return (1);
			t++;
		}
		i++;
	}
	return (0);
}

static uint16_t	pick_unique_sport(t_worker *workers, int n)
{
	uint16_t	sport;

	do {
		sport = (uint16_t)(49152 + (rand() % 16000));
	} while (sport_taken(sport, workers, n));
	return (sport);
}

/*
** Give every worker a distinct source port per selected scan type, so a
** reply's destination port identifies both which worker and which scan type
** it answers.
*/
static void	assign_sports(t_worker *workers, int n, const t_options *opts)
{
	int	i;
	int	t;

	i = 0;
	while (i < n)
	{
		t = 0;
		while (t < SCAN_MAX)
		{
			if (opts->scan[t])
				workers[i].sport[t] = pick_unique_sport(workers, n);
			t++;
		}
		i++;
	}
}

/* Collect a worker's selected source ports into a compact array for the BPF
** filter; returns how many there are. */
static int	worker_sports(const t_worker *w, uint16_t *out)
{
	int	t;
	int	count;

	count = 0;
	t = 0;
	while (t < SCAN_MAX)
	{
		if (w->opts->scan[t])
			out[count++] = w->sport[t];
		t++;
	}
	return (count);
}

static int	open_worker_handles(t_worker *workers, int n, const char *iface)
{
	uint16_t	sports[SCAN_MAX];
	int			count;
	int			i;

	i = 0;
	while (i < n)
	{
		count = worker_sports(&workers[i], sports);
		workers[i].p = pcap_open_for_scan(iface, sports, count,
			workers[i].opts->scan[SCAN_UDP] ? 1 : 0);
		if (!workers[i].p)
		{
			while (--i >= 0)
				pcap_close(workers[i].p);
			return (-1);
		}
		i++;
	}
	return (0);
}

/*
** Flatten the selected ports (a sparse bool array) into a compact list of port
** numbers and return how many there are. Workers stride the combined
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

static void	init_workers(t_worker *workers, int n, t_worker shared)
{
	int	i;

	for (i = 0; i < n; i++)
	{
		workers[i] = shared;
		workers[i].id = i;
		workers[i].nthreads = n;
	}
}

/*
** Run the whole scan in one pass with n = speedup + 1 workers. The
** host * port work space is strided across all workers (see worker_main), so
** every worker stays busy whether the scan is a few hosts on many ports or many
** hosts on a few ports. The extra speedup workers (ids 1..n-1) run on their own
** threads; worker 0 runs on the main thread itself, so speedup 0 collapses to a
** single inline pass. Stats are summed and handles closed once every worker has
** finished. active_ports lives on this stack frame, which outlives the workers
** (we join before returning), so a shared pointer into it is safe.
*/
int	run_scan(const t_options *opts, int sock, const char *iface,
		struct in_addr src, t_scan_result **results, t_pcap_stats *stats)
{
	t_worker	*workers;
	pthread_t	*tids;
	uint16_t	active_ports[MAX_PORTS];
	t_worker	shared;
	int			n;
	int			i;

	n = opts->speedup + 1;
	workers = calloc(n, sizeof(*workers));
	tids = calloc(n, sizeof(*tids));
	if (!workers || !tids)
		return (free(workers), free(tids), -1);
	shared = (t_worker){0};
	shared.sock = sock;
	shared.src = src;
	shared.opts = opts;
	shared.results = results;
	shared.active_ports = active_ports;
	shared.nports = collect_active_ports(opts, active_ports);
	init_workers(workers, n, shared);
	assign_sports(workers, n, opts);
	if (open_worker_handles(workers, n, iface) < 0)
		return (free(workers), free(tids), -1);
	for (i = 1; i < n; i++)
		pthread_create(&tids[i], NULL, worker_main, &workers[i]);
	worker_main(&workers[0]);
	for (i = 1; i < n; i++)
		pthread_join(tids[i], NULL);
	for (i = 0; i < n; i++)
	{
		stats->send_fail += workers[i].send_fail;
		accumulate_pcap_stats(workers[i].p, stats);
		pcap_close(workers[i].p);
	}
	return (free(workers), free(tids), 0);
}
