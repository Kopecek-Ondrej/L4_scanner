#ifndef __SCANNER_H_
#define __SCANNER_H_
#include "cli_eval.h"
#include "address.h"

int scan_destinations(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source);
int scan_with_tcp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source);
int scan_with_udp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source);
int read_next_port(char *s, int pos, int *port);
int get_port(Ports_t *ports);
#endif// __SCANNER_H_