#include "test_scanner.h"
#include "error_code.h"
#include "helper.h"
#include "protocol.h"
#include "parser.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

// Expect NULL argument handling to short-circuit with ERR_NO_ARGUMENTS
int test_send_with_tcp_null_args(void) {
    Parser_t parser = {0};
    Source_address_t source = {0};
    Table_packet_t table = {0};
    int rc = send_with_tcp(NULL, &parser, &source, &table);
    ASSERT_EQ_INT(ERR_NO_ARGUMENTS, rc, "send_with_tcp should fail on NULL target");
    return 0;
}

// Expect libnet_init failure for an invalid interface name and propagated error code
int test_send_with_tcp_invalid_interface(void) {
    Parser_t parser = {0};
    parser.interface = "__nonexistent_if__";
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.type = SINGLE;
    parser.tcp_ports.min = 80;

    Resolved_address_t dest = {0};
    dest.family = AF_INET;
    dest.addr.raddr4 = htonl(INADDR_LOOPBACK);

    Source_address_t source = {0};
    source.addr4 = htonl(INADDR_LOOPBACK);
    source.is_ipv4 = true;

    Packet_t packets[1] = {0};
    Table_packet_t table = {.packets = packets, .size = 1, .next_seq = 0};

    int rc = send_with_tcp(&dest, &parser, &source, &table);
    ASSERT_EQ_INT(EXIT_FAILURE, rc, "send_with_tcp should report libnet init failure");
    return 0;
}

// Ensure table bookkeeping stays untouched when init fails
int test_send_with_tcp_table_not_modified_on_init_fail(void) {
    Parser_t parser = {0};
    parser.interface = "__nonexistent_if__";
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.type = SINGLE;
    parser.tcp_ports.min = 443;

    Resolved_address_t dest = {0};
    dest.family = AF_INET6; // any family; init still fails on bad interface

    Source_address_t source = {0};
    source.is_ipv6 = true;

    Packet_t packets[2] = {0};
    Table_packet_t table = {.packets = packets, .size = 2, .next_seq = 1};

    int rc = send_with_tcp(&dest, &parser, &source, &table);
    ASSERT_EQ_INT(EXIT_FAILURE, rc, "send_with_tcp should propagate init failure");
    ASSERT_EQ_INT(1, table.next_seq, "next_seq must remain unchanged on failure");
    ASSERT_EQ_INT(ST_PENDING, packets[1].status, "status of untouched packet stays default");
    return 0;
}
