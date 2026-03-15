#include "address.h"
#include "error_code.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdbool.h>



int is_ipv6(const char *ip)
{
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip, &(sa.sin6_addr)) == 1;
}

int is_ipv4(const char *ip)
{
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1;
}

int resolve_hostname(Scanner_t *scanner, Destination_addresses_t *destination){
    // first check if the host isn't already an address
    struct sockaddr_in sa4;
    struct sockaddr_in6 sa6;
    int err = 0;

    memset(destination, 0, sizeof(*destination));

    if(inet_pton(AF_INET, scanner->hostname, &(sa4.sin_addr)) == 1){
        destination->items = calloc(1, sizeof(Resolved_address_t));
        if(destination->items == NULL){
            RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Memory allocation failure");
        }
        destination->capacity = 1;
        destination->count = 1;
        destination->has_ipv4 = true;
        destination->items[0].family = AF_INET;
        destination->items[0].addr_len = sizeof(struct sockaddr_in);
        memset(&destination->items[0].addr, 0, sizeof(destination->items[0].addr));
        memcpy(&destination->items[0].addr, &sa4, sizeof(struct sockaddr_in));
        DEBUG_PRINT("User HOST is ipv4");
        return EXIT_OK;
    }

    if(inet_pton(AF_INET6, scanner->hostname, &(sa6.sin6_addr)) == 1){
        destination->items = calloc(1, sizeof(Resolved_address_t));
        if(destination->items == NULL){
            RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Memory allocation failure");
        }
        destination->capacity = 1;
        destination->count = 1;
        destination->has_ipv6 = true;
        destination->items[0].family = AF_INET6;
        destination->items[0].addr_len = sizeof(struct sockaddr_in6);
        memset(&destination->items[0].addr, 0, sizeof(destination->items[0].addr));
        memcpy(&destination->items[0].addr, &sa6, sizeof(struct sockaddr_in6));
        DEBUG_PRINT("User HOST is ipv6");
        return EXIT_OK;
    }

    // otherwise resolve the domain name
    err = resolve_destination(scanner->hostname, destination);
    if(err != EXIT_OK) return err;

    return EXIT_OK;
}

void free_destination_addresses(Destination_addresses_t *destination)
{
    if (destination == NULL)
        return;

    free(destination->items);
    destination->items = NULL;
    destination->count = 0;
    destination->capacity = 0;
    destination->has_ipv4 = false;
    destination->has_ipv6 = false;
}

int resolve_destination(const char *hostname, Destination_addresses_t *destination)
{
    memset(destination, 0, sizeof(*destination));

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *result_p = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      // IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;  // or 0 if you do not care here

    int rc = getaddrinfo(hostname, NULL, &hints, &result);
    if (rc != 0) {
        RETURN_ERROR(ERR_RESOLVE_HOST,
                    "Failed to resolve host '%s': %s",
                    hostname,
                    gai_strerror(rc));
    }
        

    size_t count = 0;
    for (result_p = result; result_p != NULL; result_p = result_p->ai_next) {
        if (result_p->ai_family == AF_INET || result_p->ai_family == AF_INET6)
            count++;
    }

    if (count == 0) {
        freeaddrinfo(result);
        RETURN_ERROR(ERR_NO_USABLE_ADDR_FOUND,"Found no usable address");
    }

    destination->items = calloc(count, sizeof(Resolved_address_t));
    if (destination->items == NULL) {
        freeaddrinfo(result);
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Memory allocation failure");
    }

    destination->capacity = count;
    destination->count = 0;

    for (result_p = result; result_p != NULL; result_p = result_p->ai_next) {
        if (result_p->ai_family != AF_INET && result_p->ai_family != AF_INET6)
            continue;

        Resolved_address_t *item = &destination->items[destination->count];

        memcpy(&item->addr, result_p->ai_addr, result_p->ai_addrlen);
        item->addr_len = result_p->ai_addrlen;
        item->family = result_p->ai_family;

        if (result_p->ai_family == AF_INET)
            destination->has_ipv4 = true;
        else if (result_p->ai_family == AF_INET6)
            destination->has_ipv6 = true;

        destination->count++;
    }

    freeaddrinfo(result);

    return EXIT_OK;
}