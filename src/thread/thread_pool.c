#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_nmap.h"

/*
** Each worker owns a port stride: worker id scans every port p where
** (p - 1) % nthreads == id, sending every selected scan type. The shared
** results table is partitioned by port, so workers never write to the same
** slot — no lock needed.
*/
static void	*worker_main(void *arg)
{
	scan_run((t_worker *)arg);
	return (NULL);
}

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
		workers[i].p = pcap_open_for_scan(iface, sports, count);
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

static void	init_workers(t_worker *workers, int n, int sock,
		const t_options *opts, struct in_addr src, t_scan_result **results)
{
	int	i;

	for (i = 0; i < n; i++)
	{
		workers[i].id = i;
		workers[i].nthreads = n;
		workers[i].sock = sock;
		workers[i].src = src;
		workers[i].opts = opts;
		workers[i].results = results;
	}
}

/*
** Run the whole scan in one pass with n = speedup + 1 strides. Each worker
** sends every selected scan type across its stride, then collects once. The
** extra speedup workers (ids 1..n-1) run on their own threads; worker 0 runs
** on the main thread itself, so speedup 0 collapses to a single inline stride.
** Stats are summed and handles closed once every worker has finished.
*/
int	run_scan(const t_options *opts, int sock, const char *iface,
		struct in_addr src, t_scan_result **results, t_pcap_stats *stats)
{
	t_worker	*workers;
	pthread_t	*tids;
	int			n;
	int			i;

	n = opts->speedup + 1;
	workers = calloc(n, sizeof(*workers));
	tids = calloc(n, sizeof(*tids));
	if (!workers || !tids)
		return (free(workers), free(tids), -1);
	init_workers(workers, n, sock, opts, src, results);
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
		accumulate_pcap_stats(workers[i].p, stats);
		pcap_close(workers[i].p);
	}
	return (free(workers), free(tids), 0);
}
