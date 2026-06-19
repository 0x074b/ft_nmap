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

	/* scan result */

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
size_t	build_syn_packet(uint8_t *buf, struct in_addr src, struct in_addr dst,
			uint16_t sport, uint16_t dport);

	/* pcap/ */
pcap_t	*pcap_open_for_scan(const char *iface, uint16_t sport);

	/* scanner/ */
int		syn_scan_port(int sock, pcap_t *p,
			struct in_addr src, uint16_t sport,
			struct in_addr dst, uint16_t dport,
			uint32_t timeout_ms, t_port_state *state);

	/* report/ */
const char	*port_state_name(t_port_state s);
void		report_port(const char *input, struct in_addr addr,
				uint16_t port, t_port_state state, uint16_t sport);

# include "parsing.h"

#endif