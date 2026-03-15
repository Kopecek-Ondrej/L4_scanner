#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "test_interface.h"
#include "helper.h"
#include "interface.h"
#include "error_code.h"

int test_interfaces_output(void)
{
    char output[256];

    capture_stdout(output, sizeof(output), (void (*)(void))print_interfaces);

    if (strstr(output, "lo") == NULL) {
        fprintf(stderr, "FAIL: lo not printed\n");
        return 1;
    }

    if (strstr(output, "eth0") == NULL) {
        fprintf(stderr, "FAIL: eth0 not printed\n");
        return 1;
    }

    return 0;
}

int test_check_user_input_lo(void){
    Scanner_t scanner = {0};
    scanner.interface = "lo";
    Source_address_t source = {0};


    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}

int test_check_user_input_eth0(void){
    Scanner_t scanner = {0};
    scanner.interface = "eth0";
    Source_address_t source = {0};

    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}

int test_ipv4_address_from_eth0(void){
    Scanner_t scanner = {0};
    scanner.interface = "eth0";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv4){
        struct sockaddr_in *addr = (struct sockaddr_in *)&source.addr_ipv4;
        inet_ntop(AF_INET, &addr->sin_addr, str, sizeof(str));

        ASSERT_EQ_STR(str, "254.44.209.0", "expected IPv4 adress does not match ");
    }

    return 0;
}

int test_ipv6_address_from_eth0(void){
    Scanner_t scanner = {0};
    scanner.interface = "eth0";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv6){
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&source.addr_ipv6;
        inet_ntop(AF_INET6, &addr6->sin6_addr, str, sizeof(str));

        ASSERT_EQ_STR(str, "fe80::215:5dff:fe2c:d100", "expected IPv6 adress does not match ");
    }

    return 0;
}

int test_ipv4_address_from_lo(void){
    Scanner_t scanner = {0};
    scanner.interface = "lo";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv4){
        struct sockaddr_in *addr = (struct sockaddr_in *)&source.addr_ipv4;
        inet_ntop(AF_INET, &addr->sin_addr, str, sizeof(str));

        ASSERT_EQ_STR(str, "0.0.0.1", "expected IPv4 adress does not match ");
    }

    return 0;
}

int test_ipv6_address_from_lo(void){
    Scanner_t scanner = {0};
    scanner.interface = "lo";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&scanner,&source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv6){
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&source.addr_ipv6;
        inet_ntop(AF_INET6, &addr6->sin6_addr, str, sizeof(str));

        ASSERT_EQ_STR(str, "::1", "expected IPv6 adress does not match ");
    }

    return 0;
}