#include "adress.h"

#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdbool.h>

//those are max length of adresses
#define IPV4_ADDR_LEN 16 //+ null terminator
#define IPV6_ADDR_LEN 40 //+ null terminator

typedef struct{
    bool is_IPv6;
    bool is_IPv4;
    char IPv4_array[16];
    char IPv6_array[30]; //fixme toto je nevhodne pro vice IP adress
}Adress_t;

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

//pouzit strstr() na is in www.
//tady bude funkce ktera dostane jako parametr hostname taky dostane ukazatel na datovou strukturu Communication

int translate_host_name()