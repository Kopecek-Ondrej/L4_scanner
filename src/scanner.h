#ifndef __SCANNER_H_
#define __SCANNER_H_
#include "address.h"
#include "cli_eval.h"
#include "protocol.h"
#include <libnet.h>

typedef struct {
    // Raw_sockets_t* socks;
    Packet_t* table;
    int size;
    volatile int* running; // flag to stop receiver thread
} Thread_args_t;

// void receive_packets(Raw_sockets_t* socks, Packet_t* packet_table, int table_size);
int send_packets(Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table);
int send_with_tcp(Resolved_address_t* times, Parser_t* parser, Source_address_t* source, Table_packet_t* table);
int send_with_udp(Resolved_address_t* times, Parser_t* parser, Source_address_t* source, Table_packet_t* table);

int read_next_port(char* s, int pos, int* port);
int get_port(Ports_t* ports, Table_packet_t* table, Resolved_address_t* items, proto_t protocol, int iter, uint16_t src_port, Source_address_t* src_addr);
int compare_ip(struct sockaddr* a, struct sockaddr* b);
void* receiver_thread_func(void* arg);
long get_elapsed_ms(struct timespec start);

int dispatch_tcp_packet(libnet_t* lib, int family, Source_address_t* source,
    Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
    libnet_ptag_t* tcp_tag, libnet_ptag_t* ip_tag);

void handle_icmp_v4(const u_char *icmp_ptr, Table_packet_t *table);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
int setup_pcap_filter(pcap_t *handle, Destination_addresses_t *dest);
int send_single_tcp_packet(Packet_t * packet, Parser_t *parser);
int receive_packets(Parser_t *parser, Destination_addresses_t *dest, Table_packet_t* table) ;
int scan_destinations(Parser_t *parser, Destination_addresses_t *destination, Source_address_t *source, Table_packet_t *table) ;

#endif // __SCANNER_H_