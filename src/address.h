#ifndef __ADDRESS_H_
#define __ADDRESS_H_

#include <stddef.h>
#include <stdbool.h>
#include <ifaddrs.h>
#include "cli_eval.h"
//those are max length of adresses
#define IPV4_ADDR_LEN 16 //+ null terminator
#define IPV6_ADDR_LEN 40 //+ null terminator

typedef struct{
    bool is_ipv6;
    bool is_ipv4;
    struct sockaddr addr_ipv6;
    struct sockaddr addr_ipv4;
}Source_address_t;

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int family;
} Resolved_address_t;

typedef struct {
    Resolved_address_t *items;
    size_t count;
    size_t capacity;
    bool has_ipv4;
    bool has_ipv6;
} Destination_addresses_t;


#include <arpa/inet.h>
#include <netinet/in.h>

#define ADDR_TO_STR(addr, buf)                                                   \
    do {                                                                         \
        if ((addr)->sa_family == AF_INET) {                                      \
            inet_ntop(AF_INET,                                                   \
                     &((struct sockaddr_in *)(addr))->sin_addr,                  \
                     (buf), INET6_ADDRSTRLEN);                                   \
        } else if ((addr)->sa_family == AF_INET6) {                              \
            inet_ntop(AF_INET6,                                                  \
                     &((struct sockaddr_in6 *)(addr))->sin6_addr,                \
                     (buf), INET6_ADDRSTRLEN);                                   \
        } else {                                                                 \
            (buf)[0] = '\0';                                                     \
        }                                                                        \
    } while (0)

/* Resolves hostname to IPv4 string. Returns 0 on success, -1 on error. */
int resolve_hostname(Scanner_t *scanner, Destination_addresses_t *destination);
void free_destination_addresses(Destination_addresses_t *destination);

int resolve_destination(const char *hostname, Destination_addresses_t *out);

#endif // __ADDRESS_H_