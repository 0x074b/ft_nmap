#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ft_nmap.h"

/*
** Each worker owns a port stride: thread id t scans every port p where
** (p - 1) % nthreads == id. Within its stride it walks every host. The
** shared results table is partitioned by port, so threads never write to
** the same slot — no lock needed.
*/
static void	*worker_main(void *arg)
{
	t_worker	*w = arg;

	scan_stride(w->sock, w->p, w->src, w->sport, w->opts,
		w->scan_type, w->id, w->nthreads, w->results);
	return (NULL);
}

/*
** Returns true if sport collides with any sport already chosen for
** threads [0..upto). Linear scan is fine — N <= MAX_SPEEDUP (250).
*/
static int	sport_taken(uint16_t sport, t_worker *workers, int upto)
{
	int	i;

	i = 0;
	while (i < upto)
	{
		if (workers[i].sport == sport)
			return (1);
		i++;
	}
	return (0);
}

static uint16_t	pick_unique_sport(t_worker *workers, int upto)
{
	uint16_t	sport;

	do {
		sport = (uint16_t)(49152 + (rand() % 16000));
	} while (sport_taken(sport, workers, upto));
	return (sport);
}

static int	open_worker_handles(t_worker *workers, int n, const char *iface)
{
	int	i;

	i = 0;
	while (i < n)
	{
		workers[i].sport = pick_unique_sport(workers, i);
		workers[i].p = pcap_open_for_scan(iface, workers[i].sport);
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

int	run_scan_threaded(const t_options *opts, int sock,
		t_scan_type scan_type, const char *iface, struct in_addr src,
		t_scan_result **results)
{
	t_worker	*workers;
	pthread_t	*tids;
	int			n;
	int			i;

	n = opts->speedup;
	workers = calloc(n, sizeof(*workers));
	tids = calloc(n, sizeof(*tids));
	if (!workers || !tids)
		return (free(workers), free(tids), -1);
	for (i = 0; i < n; i++)
	{
		workers[i].id = i;
		workers[i].nthreads = n;
		workers[i].sock = sock;
		workers[i].src = src;
		workers[i].scan_type = scan_type;
		workers[i].opts = opts;
		workers[i].results = results;
	}
	if (open_worker_handles(workers, n, iface) < 0)
		return (free(workers), free(tids), -1);
	for (i = 0; i < n; i++)
		pthread_create(&tids[i], NULL, worker_main, &workers[i]);
	for (i = 0; i < n; i++)
		pthread_join(tids[i], NULL);
	for (i = 0; i < n; i++)
		pcap_close(workers[i].p);
	free(workers);
	free(tids);
	return (0);
}
