#include "test_interface.h"
#include "error_code.h"
#include "helper.h"
#include "interface.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

int test_interfaces_output(void) {
    char output[256];

    capture_stdout(output, sizeof(output), (void (*)(void))print_interfaces);

    if(strstr(output, "lo") == NULL) {
        fprintf(stderr, "FAIL: lo not printed\n");
        return 1;
    }

    if(strstr(output, "eth0") == NULL) {
        fprintf(stderr, "FAIL: eth0 not printed\n");
        return 1;
    }

    return 0;
}

int test_check_user_input_lo(void) {
    Parser_t parser = {0};
    parser.interface = "lo";
    Source_address_t source = {0};

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}

int test_check_user_input_eth0(void) {
    Parser_t parser = {0};
    parser.interface = "eth0";
    Source_address_t source = {0};

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}

int test_ipv4_address_from_eth0(void) {
    Parser_t parser = {0};
    parser.interface = "eth0";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv4) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&source.addr4;
        inet_ntop(AF_INET, &addr->sin_addr, str, sizeof(str));

        ASSERT_EQ_STR("254.44.209.0", str, "expected IPv4 adress does not match ");
    }

    return 0;
}

int test_ipv6_address_from_eth0(void) {
    Parser_t parser = {0};
    parser.interface = "eth0";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&source.addr6;
        inet_ntop(AF_INET6, &addr6->sin6_addr, str, sizeof(str));

        ASSERT_EQ_STR("fe80::215:5dff:fe2c:d100", str, "expected IPv6 adress does not match ");
    }

    return 0;
}

int test_ipv4_address_from_lo(void) {
    Parser_t parser = {0};
    parser.interface = "lo";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv4) {
        struct sockaddr_in* addr = (struct sockaddr_in*)&source.addr4;
        inet_ntop(AF_INET, &addr->sin_addr, str, sizeof(str));

        ASSERT_EQ_STR("0.0.0.1", str, "expected IPv4 adress does not match ");
    }

    return 0;
}

int test_ipv6_address_from_lo(void) {
    Parser_t parser = {0};
    parser.interface = "lo";
    Source_address_t source = {0};
    char str[INET6_ADDRSTRLEN];

    int rc = check_for_interface(&parser, &source);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    if(source.is_ipv6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&source.addr6;
        inet_ntop(AF_INET6, &addr6->sin6_addr, str, sizeof(str));

        ASSERT_EQ_STR("::1", str, "expected IPv6 adress does not match ");
    }

    return 0;
}