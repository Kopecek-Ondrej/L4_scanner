#include "interface.h"
#include "address.h"
#include "error_code.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>

int print_interfaces() {
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;
    struct ifaddrs* prev = NULL;

    if(getifaddrs(&ifaddr) == -1) {
        RETURN_ERROR(ERR_SYS_INTERFACE, "Failed to call getifaddrs()");
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_name == NULL)
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

int check_for_interface(Scanner_t* scanner, Source_address_t* source) {
    if(scanner == NULL || scanner->interface == NULL || source == NULL) {
        RETURN_ERROR(ERR_CLI_ARG, "Interface not specified");
    }
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;
    bool found = false;

    if(getifaddrs(&ifaddr) == -1) {
        RETURN_ERROR(ERR_SYS_INTERFACE, "Failed to call getifaddrs()");
    }

    source->is_ipv4 = false;
    source->is_ipv6 = false;

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_name == NULL || ifa->ifa_name == NULL)
            continue;

        if(strcmp(ifa->ifa_name, scanner->interface) == 0) {
            found = true;
            // here I must get the IPv4 and IPv6 adresses from for the source of communcation
            int family = ifa->ifa_addr->sa_family;
            DEBUG_PRINT("Checking %s, family: %d", ifa->ifa_name, family);

            if(family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                // Ukládáme přímo uint32_t pro libnet
                source->addr4 = sin->sin_addr.s_addr;
                source->is_ipv4 = true;
                DEBUG_PRINT("Captured IPv4");

            } else if(family == AF_INET6) {
                struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
                // Kopírujeme čistých 16 bajtů adresy do libnet_in6_addr
                memcpy(&source->addr6, &sin6->sin6_addr, sizeof(struct libnet_in6_addr));
                source->is_ipv6 = true;
                DEBUG_PRINT("capture IPv6");
            }
        }
    }

    freeifaddrs(ifaddr);

    if(found && (source->is_ipv4 || source->is_ipv6)) {
        return EXIT_OK;
    }

    RETURN_ERROR(ERR_NO_INTERFACE_FOUND, "Entered interface: %s cannot be reached", scanner->interface);
}
