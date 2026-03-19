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

static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

#define IPV4 4
#define IPV6 6

void* receiver_thread_func(void* arg) {
    Thread_args_t* targs = (Thread_args_t*)arg;
    while(*(targs->running)) {
        receive_packets(targs->socks, targs->table, targs->size);
    }
    return NULL;
}

int scan_destinations(Scanner_t* scanner, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
}

void receive_packets(Raw_sockets_t* socks, Packet_t* packet_table, int table_size) {
}

int send_packets(Scanner_t* scanner, Destination_addresses_t* destination, Source_address_t* source, Raw_sockets_t* socks, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source, socks);
    int err = 0;
    for(size_t i = 0; i < destination->count; i++) {
        // todo:: funkce ktera bude dava validni vystupni port
        if(scanner->tcp_use) {
            err = send_with_tcp(&(destination->items[i]), scanner, source, socks->fd[TCP4_OUT], socks->fd[TCP6_OUT], table);
            if(err != EXIT_OK)
                return err;
        }

        if(scanner->udp_use) {
            err = send_with_udp(&(destination->items[i]), scanner, source, socks->fd[UDP4_OUT], socks->fd[UDP6_OUT], table);
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

int send_with_tcp(Resolved_address_t* items, Scanner_t* scanner, Source_address_t* source, int sock4, int sock6, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, items, scanner, source, table);

    uint16_t my_source_port = 12345; // todo::urcite musi zde byt nejaky volny port//musim napsat funkci, pro detekci meho portu
    uint16_t target_port;
    libnet_ptag_t tcp4_tag = 0;
    libnet_ptag_t tcp6_tag = 0;
    libnet_t* l_v4 = NULL;
    libnet_t* l_v6 = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    for(int i = 0; i < scanner->tcp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->tcp_ports), table, items, SCAN_TCP, i);
        // 2. Odešleme paket pomocí správného socketu
        if(items->family == AF_INET && sock4 != -1) {
            l_v4 = libnet_init(LIBNET_RAW4, scanner->interface, errbuf);
            if(l_v4 == NULL) {
                fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
                return EXIT_FAILURE;
            }

            // uint32_t src_ip = libnet_get_ipaddr4(l_v4); // Get your own IP
            // uint32_t dst_ip = libnet_name2addr4(l_v4, "8.8.8.8", LIBNET_RESOLVE);

            tcp4_tag = build_tcp_ipv4(l, source->addr_ipv4, items->addr, my_source_port, target_port, tcp4_tag);
            if(tcp_tag == -1) {
                fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(l_v4));
                libnet_destroy(l_v4);
                return EXIT_FAILURE;
            }
            int bytes_sent = libnet_write(l_v4);
            if(bytes_sent == -1) {
                fprintf(stderr, "Write error: %s\n", libnet_geterror(l_v4));
            } else {
                printf("Successfully sent %d byte SYN packet to port %d\n", bytes_sent, target_port);
            }
        } else if(items->family == AF_INET6 && sock6 != -1) { // todo:: fix -1 as magic num
            // todo:: predavam ty parametry spatne musim je predelat, uvnitr funkce prijimaji jine typy

            l_v6 = libnet_init(LIBNET_RAW6, scanner->interface, errbuf);
            if(l_v6 == NULL) {
                fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
                return EXIT_FAILURE;
            }

            // uint32_t src_ip = libnet_get_ipaddr4(l_v4); // Get your own IP
            // uint32_t dst_ip = libnet_name2addr4(l_v4, "8.8.8.8", LIBNET_RESOLVE);

            tcp6_tag = build_tcp_ipv6(l, source->addr_ipv6, items->addr, my_source_port, target_port, tcp6_tag);
            if(tcp_tag == -1) {
                fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(l_v4));
                libnet_destroy(l_v6);
                return EXIT_FAILURE;
            }
            int bytes_sent = libnet_write(l_v6);
            if(bytes_sent == -1) {
                fprintf(stderr, "Write error: %s\n", libnet_geterror(l_v6));
            } else {
                printf("Successfully sent %d byte SYN packet to port %d\n", bytes_sent, target_port);
            }
        }

        packet_size = 0;
    }
    return EXIT_OK;
}

int send_with_udp(Resolved_address_t* items, Scanner_t* scanner, Source_address_t* source, int sock4, int sock6, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, items, scanner, source);

    char send_buffer[4096];
    int packet_size = 0;
    uint16_t my_source_port = 12345;
    uint16_t target_port;

    for(int i = 0; i < scanner->udp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->udp_ports), table, items, SCAN_UDP, i);

        if(items->family == AF_INET && sock4 != -1) {
            // build_udp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);

            if(sendto(sock4, send_buffer, packet_size, 0,
                      (struct sockaddr*)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání UDP IPv4 selhalo");
            }
        } else if(items->family == AF_INET6 && sock6 != -1) {
            build_udp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);

            if(sendto(sock6, send_buffer, packet_size, 0,
                      (struct sockaddr*)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání UDP IPv6 selhalo");
            }
        }
        packet_size = 0;
    }
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
    p->addr_len = items->addr_len;
    p->family = items->family;
    memcpy(&p->target_addr, &items->addr, items->addr_len);
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