/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include "cli_parser.h"
#include "destination.h"
#include "error_code.h"
#include "scanner.h"
#include "source.h"

static void print_answers(const Table_packet_t* table) {
    if(table == NULL || table->packets == NULL) {
        return;
    }

    for(int i = 0; i < table->size; i++) {
        const Packet_t* p = &table->packets[i];

        char ip[INET6_ADDRSTRLEN] = {0};

        if(p->family == AF_INET) {
            struct in_addr a4;
            a4.s_addr = p->dst_addr.addr.raddr4;
            if(inet_ntop(AF_INET, &a4, ip, sizeof(ip)) == NULL) {
                snprintf(ip, sizeof(ip), "<invalid-ipv4>");
            }
        } else if(p->family == AF_INET6) {
            if(inet_ntop(AF_INET6, &p->dst_addr.addr.raddr6, ip, sizeof(ip)) == NULL) {
                snprintf(ip, sizeof(ip), "<invalid-ipv6>");
            }
        } else {
            snprintf(ip, sizeof(ip), "<unknown-family>");
        }

        const char* proto = (p->proto == SCAN_TCP) ? "tcp" : "udp";
        const char* status = "pending";
        switch(p->status) {
        case ST_OPEN:
            status = "open";
            break;
        case ST_CLOSED:
            status = "closed";
            break;
        case ST_FILTERED:
            status = "filtered";
            break;
        case ST_PENDING:
        default:
            status = "pending";
            break;
        }

        fprintf(stdout, "%s %u %s %s\n", ip, p->dst_port, proto, status);
    }
}

int main(int argc, char* argv[]) {
    Cli_Parser_t parser = {0};
    Arguments_t args = {0};
    Source_address_t source = {0};
    Destination_addresses_t destination = {0};
    Table_packet_t table = {0};

    int err = parse_arguments(argc, argv, &args);
    if(err != EXIT_OK) {
        return err;
    }
    err = eval_arguments(&args, &parser);
    if(err != EXIT_OK) {
        return err;
    }

    switch(parser.mode) {
    case MODE_SHOW_INTERFACE:
        // getifaddrs
        err = print_interfaces();
        if(err != EXIT_OK)
            return err;

        break;
    case MODE_SHOW_HELP:
        print_help();
        break;
    case MODE_SCAN:
        err = resolve_source(&parser, &source);
        if(err != EXIT_OK)
            return err;

        err = resolve_target(&parser, &destination, &source);
        if(err != EXIT_OK) {
            free_destination_addresses(&destination);
            return err;
        }

        table.packets = init_packets(&parser, &destination, &table.size);
        if(table.packets == NULL) {
            free_destination_addresses(&destination);
            return ERR_SYS_MEM_ALLOC;
        }
        // table.next_seq = 0;
        err = scan_destinations(&parser, &destination, &source, &table);
        if(err != EXIT_OK) {
            free_packets(table.packets);
            free_destination_addresses(&destination);
            return err;
        }

        print_answers(&table);
        free_packets(table.packets);
        free_destination_addresses(&destination);
        break;
    }

    return 0;
}