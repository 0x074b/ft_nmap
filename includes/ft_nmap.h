#ifndef FT_NMAP_H
# define FT_NMAP_H

# include <stdbool.h>
# include <stdint.h>

# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>

# include <pcap.h>

# define MAX_PORTS			1024
# define MAX_TARGETS		256
# define MAX_DECOYS			16

# define IFACE_LEN			64
# define HOST_LEN			256

# define SERVICE_LEN		64
# define VERSION_LEN		64
# define BANNER_LEN			256

	/* enum */

typedef enum e_scan_type
{
	SCAN_SYN,
	SCAN_ACK,
	SCAN_FIN,
	SCAN_NULL,
	SCAN_XMAS,
	SCAN_UDP,
	SCAN_MAX
}	t_scan_type;

typedef enum e_port_state
{
	PORT_UNKNOWN,
	PORT_OPEN,
	PORT_CLOSED,
	PORT_FILTERED,
	PORT_UNFILTERED,
	PORT_OPEN_FILTERED
}	t_port_state;

	/* scan config */

typedef struct s_timing
{
	uint32_t	timeout_ms;
	uint32_t	retries;
}	t_timing;

typedef struct s_evasion
{
	bool		fragment;
	bool		random_ttl;
	bool		random_window;
	bool		bad_checksum;
	bool		decoy;
}	t_evasion;

typedef struct s_spoof
{
	bool			enabled;
	struct in_addr	ip;
}	t_spoof;

typedef struct s_decoy
{
	struct in_addr	ip;
}	t_decoy;

	/* service detection */

typedef struct s_service
{
	uint16_t	port;

	char		name[SERVICE_LEN];
	char		product[SERVICE_LEN];
	char		version[VERSION_LEN];
	char		banner[BANNER_LEN];

	bool		detected;
}	t_service;

	/* OS fingerprint */

typedef struct s_os_signature
{
	char		name[64];

	uint8_t		ttl;
	uint16_t	window;
	uint16_t	mss;

	bool		df;

	uint8_t		tcp_options_len;
	float		confidence;
}	t_os_signature;

	/* scan result — one entry per probed port, holding the outcome of every
	** scan type run against it. state[] is indexed by t_scan_type, so a single
	** port can carry a SYN verdict, an ACK verdict, etc. side by side. */

typedef struct s_scan_result
{
	uint16_t		port;

	t_port_state	state[SCAN_MAX];

	t_service		service;
}	t_scan_result;

	/* scan target */

typedef struct s_target
{
	char				input[HOST_LEN];
	char				ip[INET_ADDRSTRLEN];
	char				hostname[HOST_LEN];

	t_scan_result		results[MAX_PORTS];

	t_os_signature		os;
}	t_target;

	/* config */

typedef struct s_config
{
	t_target		*targets;
	uint32_t		target_count;

	uint16_t		ports[MAX_PORTS];
	uint16_t		port_count;

	uint16_t		thread_count;

	bool			scans[SCAN_MAX];

	t_timing		timing;

	char			interface[IFACE_LEN];
	struct in_addr	source_ip;

	bool			resolve_dns;
	bool			version_detection;
	bool			os_detection;

	t_evasion		evasion;
	t_spoof			spoof;

	t_decoy			decoys[MAX_DECOYS];
	uint8_t			decoy_count;

	int				verbose;
}	t_config;

	/* network/ */
int		pick_interface(char *iface, struct in_addr *src);

	/* packet/ */
void	build_ip_hdr(struct iphdr *iph, struct in_addr src, struct in_addr dst,
			uint8_t protocol, uint16_t payload_len);
void	build_tcp_hdr(struct tcphdr *tcph, struct in_addr src,
			struct in_addr dst, uint16_t sport, uint16_t dport,
			t_scan_type type);
size_t	build_tcp_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
			uint16_t sport, uint16_t dport, t_scan_type type);
void	build_udp_hdr(struct udphdr *udph, struct in_addr src,
		struct in_addr dst, uint16_t sport, uint16_t dport,
		const uint8_t *payload, size_t payload_len);
size_t	build_udp_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
		uint16_t sport, uint16_t dport,
		const uint8_t *payload, size_t payload_len);

# include "parsing.h"

	/* thread/ — declared after parsing.h because t_options lives there */
typedef struct s_worker
{
	int					id;
	int					nthreads;
	int					sock;
	pcap_t				*p;
	struct in_addr		src;
	uint16_t			sport[SCAN_MAX];
	const t_options		*opts;
	t_scan_result		**results;
}	t_worker;

/*
** Capture-side counters summed across every pcap handle (each scan pass and,
** when threaded, each worker). Reported at the end so dropped replies — the
** usual cause of spurious "filtered" verdicts — are visible.
*/
typedef struct s_pcap_stats
{
	unsigned long	recv;
	unsigned long	drop;
}	t_pcap_stats;

void	accumulate_pcap_stats(pcap_t *p, t_pcap_stats *acc);
pcap_t	*pcap_open_for_scan(const char *iface, const uint16_t *sports,
		int count, int udp);

	/* scanner/ — generic, scan-type-driven; declared after parsing.h because
	** t_options lives there. The concrete per-type probe builders and reply
	** classifiers live behind scan_ops() in scanner_internal.h. */
void	scan_run(t_worker *w);

int		run_scan(const t_options *opts, int sock, const char *iface,
			struct in_addr src, t_scan_result **results, t_pcap_stats *stats);

	/* OS detection - TCP/IP fingerprinting */
void	os_detect_init(void);
void	os_extract_fingerprint(int host_idx, const struct iphdr *iph,
			const struct tcphdr *tcph);
void	os_detect_analyze(t_scan_result **results, size_t ip_count);

void	report_results(const t_options *opts, t_scan_result **results);
void	report_pcap_stats(const t_pcap_stats *stats);

#endif