#include "scanner.h"
#include "address.h"
#include "error_code.h"
#include "protocol.h"
#include <libnet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h> // struct iphdr
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
// #include <netinet/tcp_portsh>  // struct tcphdr
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

// static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;s

#define IPV4 4
#define IPV6 6

// void* receiver_thread_func(void* arg) {
//     Thread_args_t* targs = (Thread_args_t*)arg;
//     while(*(targs->running)) {
//         receive_packets(targs->socks, targs->table, targs->size);
//     }
//     return NULL;
// }

int scan_destinations(Scanner_t* scanner, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
    return send_packets(scanner, destination, source, table);
}

// void receive_packets(Raw_sockets_t* socks, Packet_t* packet_table, int table_size) {
// }

int send_packets(Scanner_t* scanner, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source);
    int err = 0;
    for(size_t i = 0; i < destination->count; i++) {
        // todo:: funkce ktera bude dava validni vystupni port
        Resolved_address_t* item = &(destination->items[i]);

        if(scanner->tcp_use) {
            err = send_with_tcp(item, scanner, source, table);
            if(err != EXIT_OK)
                return err;
        }

        if(scanner->udp_use) {
            err = send_with_udp(item, scanner, source, table);
            if(err != EXIT_OK)
                return err;
        }
    }

    if((scanner->udp_use == false) && (scanner->tcp_use == false)) {
        free_destination_addresses(destination);
        DEBUG_PRINT("udp: %d, tcp: %d", scanner->udp_use, scanner->tcp_use);
        printf("udp: %d, tcp: %d", scanner->udp_use, scanner->tcp_use);
        RETURN_ERROR(ERR_CLI_ARG, "No port has been selected");
    }

    return EXIT_OK;
}

int dispatch_udp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* udp_tag, libnet_ptag_t* ip_tag) {
    if(family == AF_INET) {
        // 1. Sestavení/Update UDP hlavičky
        // Parametry: src_port, dst_port, total_len, checksum, payload, payload_len, lib, ptag
        *udp_tag = libnet_build_udp(src_prt, dst_prt, LIBNET_UDP_H, 0,
                                    NULL, 0, lib, *udp_tag);

        // 2. Sestavení/Update IPv4 hlavičky
        // IPPROTO_UDP je zde klíčový rozdíl
        *ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H, 0, 242, 0, 64, IPPROTO_UDP, 0,
                                    source->addr4, dest->addr.raddr4, NULL, 0, lib, *ip_tag);
    } else { // AF_INET6
        // 1. Sestavení/Update UDP hlavičky (stejné jako u v4)
        *udp_tag = libnet_build_udp(src_prt, dst_prt, LIBNET_UDP_H, 0,
                                    NULL, 0, lib, *udp_tag);

        // 2. Sestavení/Update IPv6 hlavičky
        *ip_tag = libnet_build_ipv6(0, 0, LIBNET_UDP_H, IPPROTO_UDP, 64,
                                    source->addr6, dest->addr.raddr6, NULL, 0, lib, *ip_tag);
    }

    // Kontrola chyb při sestavování
    if(*udp_tag == -1 || *ip_tag == -1) {
        fprintf(stderr, "Error building UDP packet: %s\n", libnet_geterror(lib));
        return -1;
    }

    // Odeslání paketu
    if(libnet_write(lib) == -1) {
        fprintf(stderr, "Write error (UDP): %s\n", libnet_geterror(lib));
        return -1;
    }

    return 0;
}

int dispatch_tcp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* tcp_tag, libnet_ptag_t* ip_tag) {
    if(family == AF_INET) {
        // TCP head
        *tcp_tag = libnet_build_tcp(src_prt, dst_prt, 0x01020304, 0, TH_SYN, 32767, 0, 0,
                                    LIBNET_TCP_H, NULL, 0, lib, *tcp_tag);

        // ipv4 head
        *ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64, IPPROTO_TCP, 0,
                                    source->addr4, dest->addr.raddr4, NULL, 0, lib, *ip_tag);
    } else {
        // tcp head
        *tcp_tag = libnet_build_tcp(src_prt, dst_prt, 0x01020304, 0, TH_SYN, 32767, 0, 0,
                                    LIBNET_TCP_H, NULL, 0, lib, *tcp_tag);
        // ipv6 head
        *ip_tag = libnet_build_ipv6(0, 0, LIBNET_TCP_H, IPPROTO_TCP, 64,
                                    source->addr6, dest->addr.raddr6, NULL, 0, lib, *ip_tag);
    }

    if(*tcp_tag == -1 || *ip_tag == -1) {
        fprintf(stderr, "Error building packet: %s\n", libnet_geterror(lib));
        return -1;
    }

    if(libnet_write(lib) == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(lib));
        return -1;
    }

    return 0;
}

int send_with_tcp(Resolved_address_t* item, Scanner_t* scanner, Source_address_t* source, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, item, scanner, source, table);

    uint16_t my_source_port = 12345; // todo::urcite musi zde byt nejaky volny port//musim napsat funkci, pro detekci meho portu
    uint16_t target_port;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag = 0;
    libnet_ptag_t ip_tag = 0;

    int libnet_mode = (item->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, scanner->interface, errbuf);

    if(lib == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    for(int i = 0; i < scanner->tcp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->tcp_ports), table, item, SCAN_TCP, i);

        if(dispatch_tcp_packet(lib, item->family, source, item, my_source_port, target_port, &tcp_tag, &ip_tag) == 0) {
            DEBUG_PRINT("sent syn to %d", target_port);

        } else {
            // if sending fails we continue
            fprintf(stderr, "Failed to dispatch YCP packet to port: %d\n", target_port);
        }
    }
    libnet_destroy(lib);
    return EXIT_OK;
}

int send_with_udp(Resolved_address_t* item, Scanner_t* scanner, Source_address_t* source, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, item, scanner, source, table);

    uint16_t my_source_port = 54321; // it has been recommended to keep this one fixed
    uint16_t target_port;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t udp_tag = 0;
    libnet_ptag_t ip_tag = 0;

    int libnet_mode = (item->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, scanner->interface, errbuf);

    if(lib == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    for(int i = 0; i < scanner->udp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->udp_ports), table, item, SCAN_UDP, i);

        if(dispatch_tcp_packet(lib, item->family, source, item, my_source_port, target_port, &udp_tag, &ip_tag) == 0) {
#ifdef DEBUG
            printf("DEBUG: UDP packet sent to port %d\n", target_port);
#endif
        } else {
            // if sending fails we continue
            fprintf(stderr, "Failed to dispatch YCP packet to port: %d\n", target_port);
        }
    }
    libnet_destroy(lib);
    return EXIT_OK;
}

static int port_from_list(const char* s, int index, int* port) {
    int pos = 0;
    int current = 0;

    while(s[pos] != '\0') {
        pos = read_next_port((char*)s, pos, port);
        if(current == index) {
            return EXIT_OK;
        }
        current++;
    }
    return ERR_CLI_ARG;
}

int get_port(Ports_t* ports, Table_packet_t* table, Resolved_address_t* items, proto_t protocol, int iter) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, ports, table, items);

    if(iter >= ports->port_cnt) {
        RETURN_ERROR(ERR_CLI_ARG, "Port index out of range");
    }

    int port = -1;
    switch(ports->type) {
    case SINGLE:
        port = ports->min;
        break;

    case RANGE:
        port = ports->min + iter;
        break;

    case MULTIP:
        if(port_from_list(ports->ports_array, iter, &port) != EXIT_OK) {
            RETURN_ERROR(ERR_CLI_ARG, "Invalid port list");
        }
        break;
    }

    if(table->next_seq >= table->size) {
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Packet table overflow");
    }

    int idx = table->next_seq++;
    Packet_t* p = &table->packets[idx];

    p->seq_number = (uint32_t)idx;
    p->tries = 1;
    p->status = ST_PENDING;
    p->port = port;
    p->proto = protocol;
    // p->addr_len = items->addr_len;
    p->family = items->family;
    memcpy(&p->target_addr, &items->addr, sizeof(items->addr));
    clock_gettime(CLOCK_MONOTONIC, &(p->last_sent));

    return port;
}

int read_next_port(char* s, int pos, int* port) {
    int value = 0;

    while(s[pos] != '\0' && s[pos] != ',') {
        value = value * 10 + (s[pos] - '0');
        pos++;
    }

    *port = value;

    printf("%d\n", value);

    if(s[pos] == ',')
        pos++; // skip comma

    return pos;
}

long get_elapsed_ms(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    // Rozdíl v sekundách převedený na ms + rozdíl v nanosekundách převedený na ms
    long seconds = now.tv_sec - start.tv_sec;
    long nanoseconds = now.tv_nsec - start.tv_nsec;

    return (seconds * 1000) + (nanoseconds / 1000000);
}

int compare_ip(struct sockaddr* a, struct sockaddr* b) {
    if(a->sa_family != b->sa_family)
        return 0;
    if(a->sa_family == AF_INET) {
        return ((struct sockaddr_in*)a)->sin_addr.s_addr == ((struct sockaddr_in*)b)->sin_addr.s_addr;
    } else {
        return memcmp(&((struct sockaddr_in6*)a)->sin6_addr, &((struct sockaddr_in6*)b)->sin6_addr, 16) == 0;
    }
}

// void *receiver_thread_func(void *arg) {
//     Thread_args_t *args = (Thread_args_t *)arg;
//     while (*(args->running)) {
//         receive_packets(args->socks, args->table->packets, args->table->size);
//     }
//     return NULL;
// }