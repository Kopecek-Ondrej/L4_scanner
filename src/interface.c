#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>
#include "interface.h"
#include "error_code.h"
#include "address.h"

int print_interfaces(){

    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *prev = NULL;

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

int check_for_interface(Scanner_t *scanner, Source_address_t *source){
    if (scanner == NULL || scanner->interface == NULL || source == NULL) {
        RETURN_ERROR(ERR_CLI_ARG, "Interface not specified");
    }
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    bool found = false;

    if(getifaddrs(&ifaddr) == -1) {
        RETURN_ERROR(ERR_SYS_INTERFACE, "Failed to call getifaddrs()");
    }

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if(ifa->ifa_name == NULL)
            continue;

        if(strcmp(ifa->ifa_name,scanner->interface) == 0){
            //here I must get the IPv4 and IPv6 adresses from for the source of communcation
            if(ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                memcpy(&source->addr_ipv4, sin, sizeof(struct sockaddr_in));
                source->is_ipv4 = true;
#ifdef DEBUG
                char ip[INET6_ADDRSTRLEN];
                ADDR_TO_STR(ifa->ifa_addr, ip);
                DEBUG_PRINT("IPv4 Adress: %s",ip);
#endif
            }

            else if(ifa->ifa_addr->sa_family == AF_INET6) {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                memcpy(&source->addr_ipv6, sin6, sizeof(struct sockaddr_in6));
                source->is_ipv6 = true;
#ifdef DEBUG
                char ip[INET6_ADDRSTRLEN];
                ADDR_TO_STR(ifa->ifa_addr, ip);
                DEBUG_PRINT("IPv6 Adress: %s",ip);
#endif
            }
            found = true;
        }
    }

    freeifaddrs(ifaddr);

    if(found){
        return EXIT_OK;
    }

    RETURN_ERROR(ERR_NO_INTERFACE_FOUND, "Entered interface: %s cannot be reached", scanner->interface); 
}
