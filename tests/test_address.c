#include "test_address.h"
#include "cli_eval.h"
#include "address.h"
#include "error_code.h"
#include "helper.h"


int test_resolve_hostname_user_set_ipv4(void){
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "150.24.155.5";
    
    int rc = resolve_hostname(&scanner, &destination);

    char ip[INET6_ADDRSTRLEN];
    ADDR_TO_STR((struct sockaddr *)&destination.items[0].addr, ip);

    ASSERT_EQ_STR("150.24.155.5", ip, "expected IPv4 adress does not match ");
    ASSERT_EQ_INT(EXIT_OK, rc, "expected to exit ok");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_set_ipv6(void){
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    
    int rc = resolve_hostname(&scanner, &destination);

    char ip[INET6_ADDRSTRLEN];
    ADDR_TO_STR((struct sockaddr *)&destination.items[0].addr, ip);

    ASSERT_EQ_STR("2001:db8:85a3::8a2e:370:7334", ip, "expected IPv6 adress does not match ");
    ASSERT_EQ_INT(EXIT_OK, rc, "expected to exit ok");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_invalid_ipv4(void){
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "350.24.155.5";
    
    int rc = resolve_hostname(&scanner, &destination);

    ASSERT_EQ_INT(ERR_RESOLVE_HOST, rc, "expected to fail, invalid ipv4");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_invalid_ipv6(void){
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "2001:0db8:85a3dc:0000:0000:8a2e:0370:7334";
    
    int rc = resolve_hostname(&scanner, &destination);

    ASSERT_EQ_INT(ERR_RESOLVE_HOST, rc, "expected to fail, invalid ipv6");

    free_destination_addresses(&destination);

    return 0;
}