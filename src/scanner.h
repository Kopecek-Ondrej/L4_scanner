#ifndef __SCANNER_H_
#define __SCANNER_H_
#include "cli_eval.h"
#include "address.h"
#include "protocol.h"

// typedef struct {
//     Raw_sockets_t *socks;
//     Table_packet_t *table;
//     volatile int *running; // Příznak, kdy má vlákno přestat poslouchat
// } Thread_args_t;

void receive_packets(Raw_sockets_t *socks, Packet_t *packet_table, int table_size);
int scan_destinations(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source, Table_packet_t *table);
int send_packets(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source, Raw_sockets_t *socks, Table_packet_t *table);
int send_with_tcp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source, int sock4, int sock6, Table_packet_t *table);
int send_with_udp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source, int sock4,int sock6, Table_packet_t *table);

int read_next_port(char *s, int pos, int *port);
int get_port(Ports_t *ports, Table_packet_t *table, Resolved_address_t *items, proto_t protocol, int iter);
int compare_ip(struct sockaddr *a, struct sockaddr *b);
void *receiver_thread_func(void *arg);
long get_elapsed_ms(struct timespec start);
#endif// __SCANNER_H_