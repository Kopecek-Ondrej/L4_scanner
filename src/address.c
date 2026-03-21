#include "address.h"
#include "error_code.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int is_ipv6(const char* ip) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip, &(sa.sin6_addr)) == 1;
}

int is_ipv4(const char* ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

int resolve_hostname(Parser_t* parser, Destination_addresses_t* destination) {
    // first check if the host isn't already an address
    struct addrinfo hints, *addr_list, *p;
    int status;

    destination->count = 0;
    destination->capacity = 2; // init value;
    destination->has_ipv4 = false;
    destination->has_ipv6 = false;
    destination->items = calloc(destination->capacity, sizeof(Resolved_address_t));

    if(destination->items == NULL)
        return -1; // todo:: edit errors

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if((status = getaddrinfo(parser->hostname, NULL, &hints, &addr_list)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        free(destination->items);
        return -1;
    }

    for(p = addr_list; p != NULL; p = p->ai_next) {
        if(p->ai_family != AF_INET && p->ai_family != AF_INET6)
            continue;

        if(destination->count <= destination->capacity) {
            size_t new_size = destination->capacity * 2;
            Resolved_address_t* tmp = realloc(destination->items, new_size * sizeof(Resolved_address_t)); // prisk:: dont forget to call free for this
            if(!tmp) {
                freeaddrinfo(addr_list);
                return -1; // todo:: edit error handling
            }

            destination->items = tmp;
            destination->capacity = new_size;
        }

        Resolved_address_t* current = &destination->items[destination->count];
        current->family = p->ai_family;

        if(p->ai_family == AF_INET) { // ipv4
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            current->addr.raddr4 = ipv4->sin_addr.s_addr;
            destination->has_ipv4 = true;
            destination->count++;
        } else if(p->ai_family == AF_INET6) {
            // identical to struct libnet_in6_addr both are 16B
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            memcpy(&current->addr.raddr6, &ipv6->sin6_addr, sizeof(struct libnet_in6_addr));
            destination->has_ipv6 = true;
            destination->count++;
        }
    }

    freeaddrinfo(addr_list);
    return (destination->count > 0) ? 0 : -1;
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
