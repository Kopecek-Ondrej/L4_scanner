/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#include "destination.h"
#include "error_code.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define INIT_CAP 2

Packet_t* init_packets(Cli_Parser_t* parser, Destination_addresses_t* destination, int* table_size) {
    int packets_to_allocate = 0;
    Packet_t* packets;

    // calculate number packets:( tcp_ports + udp_ports ) * number_of_destinations
    if(parser->tcp_use) {
        packets_to_allocate += parser->tcp_ports.port_cnt;
    }

    if(parser->udp_use) {
        packets_to_allocate += parser->udp_ports.port_cnt;
    }

    packets_to_allocate *= destination->count;

    packets = calloc(packets_to_allocate, sizeof(Packet_t));
    if(packets == NULL) {
        perror("calloc");
        return NULL;
    }

    *table_size = packets_to_allocate;
    return packets;
}

void free_packets(Packet_t* packets) {
    if(packets != NULL) {
        free(packets);
    }
}

int resolve_target(Cli_Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source) {
    struct addrinfo hints, *addr_list, *aux;
    int status;

    // init destination
    destination->count = 0;
    destination->capacity = INIT_CAP; // init value;
    destination->has_ipv4 = false;
    destination->has_ipv6 = false;

    destination->items = calloc(destination->capacity, sizeof(Resolved_address_t));
    if(destination->items == NULL) {
        perror("calloc");
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "");
    }

    memset(&hints, 0, sizeof(hints));
    // return socket addresses for any address family
    hints.ai_family = AF_UNSPEC;
    // prevents duplicities
    // we want to keep raw IPa anyway
    hints.ai_socktype = SOCK_STREAM;

    if((status = getaddrinfo(parser->hostname, NULL, &hints, &addr_list)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        free(destination->items);
        destination->items = NULL;
        destination->count = 0;
        destination->capacity = 0;
        RETURN_ERROR(ERR_RESOLVE_HOST, "");
    }

    for(aux = addr_list; aux != NULL; aux = aux->ai_next) {
        // FIRST evalue source capabilities
        if(aux->ai_family == AF_INET) {
            // ff the target has ipv4, but our interface doesn't, skip it.
            if(!source->is_ipv4) {
                fprintf(stderr, "[i] Skipping target IPv4: No local IPv4 available on interface.\n");
                continue;
            }
        } else if(aux->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6_check = (struct sockaddr_in6*)aux->ai_addr;

            // check if the destination is link-local or global
            if(IN6_IS_ADDR_LINKLOCAL(&ipv6_check->sin6_addr)) {
                if(!source->is_local_ipv6 && !source->is_ipv6) {
                    fprintf(stderr, "[i] Skipping target link-local IPv6: No local IPv6 available.\n");
                    continue;
                }
            } else {
                // is global
                if(!source->is_ipv6) {
                    fprintf(stderr, "[i] Skipping target global IPv6: Local interface lacks global IPv6.\n");
                    continue;
                }
            }
        } else {
            // ignore the rest of the families
            continue;
        }

        // realloc memory only when the array is full
        if(destination->count >= destination->capacity) {
            size_t new_size = destination->capacity * 2;
            Resolved_address_t* tmp = realloc(destination->items, new_size * sizeof(Resolved_address_t));
            if(tmp == NULL) {
                freeaddrinfo(addr_list);
                free(destination->items);
                perror("realloc");
                RETURN_ERROR(ERR_SYS_MEM_ALLOC, "");
            }

            destination->items = tmp;
            destination->capacity = new_size;
        }

        // save relevant addresses
        Resolved_address_t* current = &destination->items[destination->count];
        current->family = aux->ai_family;

        if(aux->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)aux->ai_addr; // c-way of overloading xd
            current->addr.raddr4 = ipv4->sin_addr.s_addr;
            destination->has_ipv4 = true;
            destination->count++;

        } else if(aux->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)aux->ai_addr;
            memcpy(&current->addr.raddr6, &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
            destination->has_ipv6 = true;
            destination->count++;
        }
    }

    freeaddrinfo(addr_list);
    return (destination->count > 0) ? EXIT_OK : ERR_RESOLVE_HOST;
}

void free_destination_addresses(Destination_addresses_t* destination) {
    if(destination == NULL)
        return;

    free(destination->items);
    destination->items = NULL;
    destination->count = 0;
    destination->capacity = 0;
    destination->has_ipv4 = false;
    destination->has_ipv6 = false;
}
