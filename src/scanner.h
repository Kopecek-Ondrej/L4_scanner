/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#ifndef __SCANNER_H_
#define __SCANNER_H_
#include "cli_parser.h"
#include "destination.h"
#include <libnet.h>

/**
 * @brief Parsed data extracted from captured packet.
 */
typedef struct {
    int family;       /**< AF_INET or AF_INET6 */
    uint8_t l4_proto; /**< IPPROTO_TCP / IPPROTO_UDP / IPPROTO_ICMP / IPPROTO_ICMPV6 */

    struct in_addr src4, dst4;
    struct in6_addr src6, dst6;

    uint16_t src_port;
    uint16_t dst_port;
    bool has_ports;

    bool tcp_rst;
    bool tcp_syn_ack;

    // ICMP unreachable -> embedded original UDP tuple
    bool icmp_udp_unreach;
    int inner_family; // AF_INET / AF_INET6
    uint16_t inner_dst_port;
    struct in_addr inner_dst4;
    struct in6_addr inner_dst6;
} Parsed_packet_t;

// void receive_packets(Raw_sockets_t* socks, Packet_t* packet_table, int table_size);
/**
 * @brief Send packets according to CLI options and destination list.
 */
int send_packets(Cli_Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table);

/**
 * @brief Dispatch TCP probes to resolved addresses.
 */
int send_with_tcp(Resolved_address_t* times, Cli_Parser_t* parser, Source_address_t* source, Table_packet_t* table);

/**
 * @brief Dispatch UDP probes to resolved addresses.
 */
int send_with_udp(Resolved_address_t* times, Cli_Parser_t* parser, Source_address_t* source, Table_packet_t* table);

/**
 * @brief Send one TCP packet using current CLI parameters.
 */
int send_single_tcp_packet(Packet_t* packet, Cli_Parser_t* parser);

/**
 * @brief Parse next port value from a string.
 */
int read_next_port(char* s, int pos, int* port);

/**
 * @brief Resolve next destination port and fill outgoing packet metadata.
 */
int get_port(Ports_t* ports, Table_packet_t* table, Resolved_address_t* items, proto_t protocol, int iter,
             uint16_t src_port, Source_address_t* src_addr, uint32_t* packet_tcp_seq);

/**
 * @brief Receive packets in a worker thread.
 */
void* receiver_thread(void* arg);

/**
 * @brief Get elapsed milliseconds since start timestamp.
 */
long get_elapsed_ms(struct timespec start);

/**
 * @brief Build and send a TCP packet with libnet.
 */
int dispatch_tcp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* tcp_tag, libnet_ptag_t* ip_tag, uint32_t* packet_tcp_seq);

/**
 * @brief Build and send a UDP packet with libnet.
 */
int dispatch_udp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* udp_tag, libnet_ptag_t* ip_tag);

/**
 * @brief Handle incoming packet capture callback.
 */
void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

/**
 * @brief Install pcap filter for captured traffic.
 */
int setup_pcap_filter(pcap_t* handle, uint32_t my_source_port);

/**
 * @brief Collect responses until timeout or stop flag.
 */
int receive_packets(Cli_Parser_t* parser, Table_packet_t* table);

/**
 * @brief Scan all targets using configured protocols.
 */
int scan_destinations(Cli_Parser_t* parser, Destination_addresses_t* destination,
                      Source_address_t* source, Table_packet_t* table);

/**
 * @brief Close dummy sockets used to open firewall states.
 */
void clean_dummy_fd(int* dummy_tcp_fd, int* dummy_udp_fd);
#endif // __SCANNER_H_