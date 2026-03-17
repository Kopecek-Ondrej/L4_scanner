#ifndef __SCANNER_H_
#define __SCANNER_H_
#include "cli_eval.h"
#include "address.h"
#include "protocol.h"

int scan_destinations(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source);
int send_packets(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source, Raw_sockets_t *socks, Packet_t *packets);
int send_with_tcp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source, int sock4, int sock6, Packet_t *packets);
int send_with_udp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source, int sock4,int sock6, Packet_t *packets);

int read_next_port(char *s, int pos, int *port);
int get_port(Ports_t *ports, Packet_t *packets, Resolved_address_t *items);
#endif// __SCANNER_H_