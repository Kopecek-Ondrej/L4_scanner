/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#ifndef __ADDRESS_H_
#define __ADDRESS_H_

#include "cli_parser.h"
#include "source.h"
#include <ifaddrs.h>
#include <libnet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

/**
 * @brief Resolved destination address for IPv4 or IPv6.
 */
typedef struct {
    union {
        uint32_t raddr4;
        struct libnet_in6_addr raddr6;
    } addr;
    int family;
} Resolved_address_t;

/**
 * @brief Protocol used for scanning.
 */
typedef enum { SCAN_TCP,
               SCAN_UDP } proto_t;

/**
 * @brief State of a scanned port.
 */
typedef enum { ST_PENDING,
               ST_OPEN,
               ST_CLOSED,
               ST_FILTERED } state_t;

/**
 * @brief Tracking data for a single probed destination/port.
 */
typedef struct {
    Resolved_address_t dst_addr; // desstination IP
    Source_address_t src_addr;
    uint16_t dst_port; // destination port
    uint16_t src_port; // source port
    proto_t proto;     // TCP or UDP

    int family; // AF_INET or AF_INET6

    // STATE INFO
    state_t status;
    int tries; // 1 OR 2
    struct timespec last_sent;

    uint32_t seq_number; // sequential number, mainly for TCP, UDP has also ones
} Packet_t;

/**
 * @brief Table of packets being probed.
 */
typedef struct {
    Packet_t* packets;
    int size;
    int next_seq;
} Table_packet_t;

/**
 * @brief Collection of resolved destination addresses.
 */
typedef struct {
    Resolved_address_t* items;
    size_t count;
    size_t capacity;
    bool has_ipv4;
    bool has_ipv6;
} Destination_addresses_t;

#define ADDR_TO_STR(addr, buf)                                    \
    do {                                                          \
        if((addr)->sa_family == AF_INET) {                        \
            inet_ntop(AF_INET,                                    \
                      &((struct sockaddr_in*)(addr))->sin_addr,   \
                      (buf), INET6_ADDRSTRLEN);                   \
        } else if((addr)->sa_family == AF_INET6) {                \
            inet_ntop(AF_INET6,                                   \
                      &((struct sockaddr_in6*)(addr))->sin6_addr, \
                      (buf), INET6_ADDRSTRLEN);                   \
        } else {                                                  \
            (buf)[0] = '\0';                                      \
        }                                                         \
    } while(0)

/**
 * @brief Allocate and initialize packet table for all destinations.
 */
Packet_t* init_packets(Cli_Parser_t* parser, Destination_addresses_t* destination, int* table_size);
/**
 * @brief Free packet table memory.
 */
void free_packets(Packet_t* packets);
/**
 * @brief Resolve hostname to address list for scanning.
 */
int resolve_target(Cli_Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source);
/**
 * @brief Release memory held by destination list.
 */
void free_destination_addresses(Destination_addresses_t* destination);

// int resolve_destination(const char* hostname, Destination_addresses_t* out);

#endif // __ADDRESS_H_