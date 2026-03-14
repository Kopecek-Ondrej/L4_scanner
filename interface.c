#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>
#include "interface.h"
#include "error_code.h"

int print_interfaces(){

    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    struct ifaddrs *prev = NULL;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;

        int already_printed = 0;

        for (prev = ifaddr; prev != ifa; prev = prev->ifa_next) {
            if (prev->ifa_name != NULL &&
                strcmp(prev->ifa_name, ifa->ifa_name) == 0) {
                already_printed = 1;
                break;
            }
        }

        if (!already_printed) {
            fprintf(stdout, "%s\n", ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
    return 0;
     
}