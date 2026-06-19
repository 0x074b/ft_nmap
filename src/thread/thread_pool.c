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
	t_worker		*w = arg;
	t_port_state	state;
	int				port;
	size_t			h;

	port = w->id + 1;
	while (port <= MAX_PORTS)
	{
		if (w->opts->ports[port])
		{
			for (h = 0; h < w->opts->ip_count; h++)
			{
				if (syn_scan_port(w->sock, w->p, w->src, w->sport,
						w->opts->ips[h].addr, (uint16_t)port,
						1000, &state) == 0)
					w->results[h][port] = state;
				else
					w->results[h][port] = PORT_FILTERED;
			}
		}
		port += w->nthreads;
	}
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
		const char *iface, struct in_addr src,
		t_port_state **results)
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
