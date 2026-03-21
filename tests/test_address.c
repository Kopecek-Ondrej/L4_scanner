#include "test_address.h"
#include "address.h"
#include "cli_eval.h"
#include "error_code.h"
#include "helper.h"
#include "scanner.h"

#include <arpa/inet.h>

int test_resolve_hostname_user_set_ipv4(void) {
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "150.24.155.5";

    int rc = resolve_hostname(&scanner, &destination);

    char ip[INET6_ADDRSTRLEN];
    ADDR_TO_STR((struct sockaddr*)&destination.items[0].addr, ip);

    ASSERT_EQ_STR("150.24.155.5", ip, "expected IPv4 adress does not match ");
    ASSERT_EQ_INT(EXIT_OK, rc, "expected to exit ok");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_set_ipv6(void) {
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";

    int rc = resolve_hostname(&scanner, &destination);

    char ip[INET6_ADDRSTRLEN];
    ADDR_TO_STR((struct sockaddr*)&destination.items[0].addr, ip);

    ASSERT_EQ_STR("2001:db8:85a3::8a2e:370:7334", ip, "expected IPv6 adress does not match ");
    ASSERT_EQ_INT(EXIT_OK, rc, "expected to exit ok");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_invalid_ipv4(void) {
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "350.24.155.5";

    int rc = resolve_hostname(&scanner, &destination);

    ASSERT_EQ_INT(ERR_RESOLVE_HOST, rc, "expected to fail, invalid ipv4");

    free_destination_addresses(&destination);

    return 0;
}

int test_resolve_hostname_user_invalid_ipv6(void) {
    Scanner_t scanner = {0};
    Destination_addresses_t destination = {0};
    scanner.hostname = "2001:0db8:85a3dc:0000:0000:8a2e:0370:7334";

    int rc = resolve_hostname(&scanner, &destination);

    ASSERT_EQ_INT(ERR_RESOLVE_HOST, rc, "expected to fail, invalid ipv6");

    free_destination_addresses(&destination);

    return 0;
}

int test_compare_ip(void) {
    struct sockaddr_in a4 = {0};
    struct sockaddr_in b4 = {0};
    struct sockaddr_in c4 = {0};
    struct sockaddr_in6 a6 = {0};

    a4.sin_family = AF_INET;
    b4.sin_family = AF_INET;
    c4.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.1", &a4.sin_addr);
    inet_pton(AF_INET, "192.168.0.1", &b4.sin_addr);
    inet_pton(AF_INET, "192.168.0.2", &c4.sin_addr);

    a6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &a6.sin6_addr);

    ASSERT_EQ_INT(1, compare_ip((struct sockaddr*)&a4, (struct sockaddr*)&b4), "compare_ip equal IPv4");
    ASSERT_EQ_INT(0, compare_ip((struct sockaddr*)&a4, (struct sockaddr*)&c4), "compare_ip different IPv4");
    ASSERT_EQ_INT(0, compare_ip((struct sockaddr*)&a4, (struct sockaddr*)&a6), "compare_ip different family");

    return EXIT_OK;
}

int test_read_next_port_basic(void) {
    char s[] = "12,34";
    int port = 0;

    int pos = read_next_port(s, 0, &port);

    ASSERT_EQ_INT(12, port, "read_next_port basic port");
    ASSERT_EQ_INT(3, pos, "read_next_port basic pos after comma");
    return EXIT_OK;
}

int test_read_next_port_second_token(void) {
    char s[] = "12,34,56";
    int port = 0;

    int pos = read_next_port(s, 3, &port);

    ASSERT_EQ_INT(34, port, "read_next_port second token port");
    ASSERT_EQ_INT(6, pos, "read_next_port second token pos");
    return EXIT_OK;
}

int test_read_next_port_trailing_comma(void) {
    char s[] = "99,";
    int port = 0;

    int pos = read_next_port(s, 0, &port);

    ASSERT_EQ_INT(99, port, "read_next_port trailing comma port");
    ASSERT_EQ_INT(3, pos, "read_next_port trailing comma pos");
    return EXIT_OK;
}

int test_get_port_variants(void) {
    Packet_t packets[5] = {0};
    Table_packet_t table = {0};
    table.packets = packets;
    table.size = 5;
    table.next_seq = 0;

    Resolved_address_t item = {0};
    item.family = AF_INET;
    // item.addr_len = sizeof(struct sockaddr_in);

    // SINGLE
    Ports_t single = {.min = 22, .max = 22, .port_cnt = 1, .type = SINGLE};
    int port = get_port(&single, &table, &item, SCAN_TCP, 0);
    ASSERT_EQ_INT(22, port, "get_port single value");

    // RANGE
    Ports_t range = {.min = 1000, .max = 1002, .port_cnt = 3, .type = RANGE};
    port = get_port(&range, &table, &item, SCAN_TCP, 2);
    ASSERT_EQ_INT(1002, port, "get_port range value");

    // MULTIP
    char list[] = "7,8,9";
    Ports_t multip = {.ports_array = list, .port_cnt = 3, .type = MULTIP};
    port = get_port(&multip, &table, &item, SCAN_UDP, 1);
    ASSERT_EQ_INT(8, port, "get_port multip value");

    // Out of range
    int rc = get_port(&multip, &table, &item, SCAN_UDP, 3);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "get_port index out of range");

    return EXIT_OK;
}