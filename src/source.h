/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#ifndef __INTERFACE_H
#define __INTERFACE_H

#include "cli_parser.h"
#include <libnet.h>

typedef struct {
    /**
     * @brief IPv4 address used for libnet packet builds.
     */
    uint32_t addr4; // Pro libnet_build_ipv4
    /**
     * @brief IPv6 address used for libnet packet builds.
     */
    struct libnet_in6_addr addr6; // Pro libnet_build_ipv6
    /**
     * @brief True when IPv4 source is set.
     */
    bool is_ipv4;
    /**
     * @brief True when IPv6 global source is set.
     */
    bool is_ipv6; // for global ipv6
    /**
     * @brief True when link-local IPv6 is set.
     */
    bool is_local_ipv6; // for link-local
} Source_address_t;

/**
 * @brief Print available network interfaces.
 */
int print_interfaces();
/**
 * @brief Resolve and store source addresses based on CLI options.
 */
int resolve_source(Cli_Parser_t* parser, Source_address_t* source);
/**
 * @brief Close dummy sockets opened during source resolution.
 */
void clean_dummy_fd(int* dummy_tcp_fd, int* dummy_udp_fd);

/**
 * @brief Obtain a free source port and optionally return open FDs.
 */
uint32_t get_available_source_port(int* out_tcp_fd, int* out_udp_fd);

#endif // __INTERFACE_H