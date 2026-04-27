/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#include "source.h"
#include "destination.h"
#include "error_code.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>

void clean_dummy_fd(int* dummy_tcp_fd, int* dummy_udp_fd) {
    if(*dummy_tcp_fd != -1) {
        close(*dummy_tcp_fd);
    }
    if(*dummy_udp_fd != -1) {
        close(*dummy_udp_fd);
    }
}

uint32_t get_available_source_port(int* out_tcp_fd, int* out_udp_fd) {
    int udp_sock, tcp_sock;
    struct sockaddr_in addr;
    socklen_t len;
    unsigned int attempt = 0;

    while(1) {
        attempt++;

        // try get free udp port
        udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if(udp_sock < 0) {
            perror("udp socket");
            return 0;
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(0); // zero = OS picks random port

        if(bind(udp_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("udp bind");
            close(udp_sock);
            return 0;
        }

        // determin, which port OS gave us
        len = sizeof(addr);
        if(getsockname(udp_sock, (struct sockaddr*)&addr, &len) < 0) {
            perror("getsockname");
            close(udp_sock);
            return 0;
        }


        // try to lock the same port also for tcp
        tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
        if(tcp_sock < 0) {
            perror("tcp socket");
            close(udp_sock);
            return 0;
        }

        // addr.sin_port has port from udp
        if(bind(tcp_sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            if(out_udp_fd)
                *out_udp_fd = udp_sock;
            else
                close(udp_sock);

            if(out_tcp_fd)
                *out_tcp_fd = tcp_sock;
            else
                close(tcp_sock);

            return ntohs(addr.sin_port);
        }


        // if it fails we close both and repeat
        close(udp_sock);
        close(tcp_sock);
    }
}

int print_interfaces() {
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;
    struct ifaddrs* prev = NULL;

    if(getifaddrs(&ifaddr) == -1) {
        RETURN_ERROR(ERR_SYS_INTERFACE, "Failed to call getifaddrs()");
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        // only for interfaces that are UP
        if(ifa->ifa_name == NULL || !(ifa->ifa_flags & IFF_UP))
            continue;

        int already_printed = 0;

        for(prev = ifaddr; prev != ifa; prev = prev->ifa_next) {
            if(prev->ifa_name != NULL &&
               strcmp(prev->ifa_name, ifa->ifa_name) == 0) {
                already_printed = 1;
                break;
            }
        }

        if(!already_printed) {
            fprintf(stdout, "%s\n", ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
    return EXIT_OK;
}

int resolve_source(Cli_Parser_t* parser, Source_address_t* source) {
    if(parser == NULL || parser->interface == NULL || source == NULL) {
        RETURN_ERROR(ERR_CLI_ARG, "Interface not specified");
    }

    struct ifaddrs* ifaddr = NULL;
    if(getifaddrs(&ifaddr) == -1) {
        RETURN_ERROR(ERR_SYS_INTERFACE, "Failed to call getifaddrs()");
    }

    source->is_ipv4 = false;
    source->is_ipv6 = false;

    bool found = false;
    bool have_link_local_ipv6 = false;
    struct libnet_in6_addr link_local_ipv6 = {0};

    for(struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_name == NULL || ifa->ifa_addr == NULL) {
            continue;
        }

        if(strcmp(ifa->ifa_name, parser->interface) == 0) {
            found = true;
            int family = ifa->ifa_addr->sa_family;

            if(family == AF_INET && !source->is_ipv4) { // Uloží jen první IPv4
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                char ip4_str[INET_ADDRSTRLEN] = {0};
                source->addr4 = sin->sin_addr.s_addr;
                source->is_ipv4 = true;
                if(inet_ntop(AF_INET, &sin->sin_addr, ip4_str, sizeof(ip4_str)) != NULL) {
                    DEBUG_PRINT("Source IPv4: %s", ip4_str);
                }
            } else if(family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
                char ip6_str[INET6_ADDRSTRLEN] = {0};

                if(inet_ntop(AF_INET6, &sin6->sin6_addr, ip6_str, sizeof(ip6_str)) == NULL) {
                    strcpy(ip6_str, "<invalid-ipv6>");
                }

                if(IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
                    if(!have_link_local_ipv6) {
                        memcpy(&link_local_ipv6, &sin6->sin6_addr, sizeof(link_local_ipv6));
                        have_link_local_ipv6 = true;
                        DEBUG_PRINT("Captured link-local IPv6 candidate: %s", ip6_str);
                    }
                } else if(!source->is_ipv6) { // Uloží jen první globální IPv6
                    memcpy(&source->addr6, &sin6->sin6_addr, sizeof(source->addr6));
                    source->is_ipv6 = true;
                }
            }

            // if we have both we stop
            if(source->is_ipv4 && source->is_ipv6) {
                break;
            }
        }
    }

    // apply fallback on link-local ipv6, if no global
    if(!source->is_ipv6 && have_link_local_ipv6) {
        source->addr6 = link_local_ipv6;
        source->is_ipv6 = false;
        source->is_local_ipv6 = true;
        fprintf(stderr, "[i] No global ipv6 address\n");
    }

    freeifaddrs(ifaddr);

    if(!found) {
        RETURN_ERROR(ERR_NO_INTERFACE_FOUND, "Interface '%s' was not found", parser->interface);
    }

    if(!source->is_ipv4 && !source->is_ipv6) {
        RETURN_ERROR(ERR_NO_INTERFACE_FOUND, "Interface '%s' exists but has no IPv4/IPv6 address", parser->interface);
    }

    return EXIT_OK;
}