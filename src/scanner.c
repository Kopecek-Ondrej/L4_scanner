#include "scanner.h"
#include "address.h"
#include "error_code.h"
#include "protocol.h"
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
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source, table);

    int err = 0;
    Raw_sockets_t socks;
    err = init_raw_sockets(&socks);
    if(err != EXIT_OK)
        RETURN_ERROR(ERR_SOCK_INIT, "Failed to initialize sockets");

    Packet_t* packets = init_packets(scanner, destination, &(table->size));
    if(packets == NULL)
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Failed to allocate memory");
    table->packets = packets;
    table->next_seq = 0;

    volatile int running = 1;
    Thread_args_t targs = {.socks = &socks, .table = table->packets, .size = table->size, .running = &running};
    pthread_t recv_thread;
    if(pthread_create(&recv_thread, NULL, receiver_thread_func, &targs) != 0) {
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Failed to start receiver thread");
    }

    err = send_packets(scanner, destination, source, &socks, table);
    if(err != EXIT_OK)
        return err;

    int pending = 1;
    while(pending) {
        pending = 0;
        for(int i = 0; i < table->size; i++) {
            pthread_mutex_lock(&table_mutex);
            Packet_t* p = &table->packets[i];
            if(p->status != ST_PENDING) {
                pthread_mutex_unlock(&table_mutex);
                continue;
            }

            pending = 1;
            long elapsed_ms = get_elapsed_ms(p->last_sent);
            pthread_mutex_unlock(&table_mutex);

            if(p->proto == SCAN_TCP) {
                pthread_mutex_lock(&table_mutex);
                if(p->tries == 1 && elapsed_ms >= scanner->timeout) {
                    pthread_mutex_unlock(&table_mutex);
                    Resolved_address_t dest = {0};
                    dest.addr_len = p->addr_len;
                    dest.family = p->family;
                    memcpy(&dest.addr, &p->target_addr, p->addr_len);

                    char send_buffer[4096];
                    int packet_size = 0;
                    uint16_t my_source_port = 12345;
                    int sock = (dest.family == AF_INET) ? socks.fd[TCP4_OUT] : socks.fd[TCP6_OUT];

                    build_tcp_packet(send_buffer, &packet_size, source, &dest, my_source_port, p->port);
                    if(sendto(sock, send_buffer, packet_size, 0,
                              (struct sockaddr*)&dest.addr, dest.addr_len) < 0) {
                        perror("Odeslání TCP selhalo");
                    }

                    clock_gettime(CLOCK_MONOTONIC, &(p->last_sent));
                    p->tries = 2;
                    pthread_mutex_unlock(&table_mutex);
                } else if(p->tries == 2 && elapsed_ms >= scanner->timeout) {
                    p->status = ST_FILTERED;
                    pthread_mutex_unlock(&table_mutex);
                } else {
                    pthread_mutex_unlock(&table_mutex);
                }
            } else { // SCAN_UDP
                pthread_mutex_lock(&table_mutex);
                if(elapsed_ms >= scanner->timeout) {
                    p->status = ST_OPEN;
                    pthread_mutex_unlock(&table_mutex);
                } else {
                    pthread_mutex_unlock(&table_mutex);
                }
            }
        }
    }

    running = 0;
    pthread_join(recv_thread, NULL);
    close_raw_sockets(&socks);

    return EXIT_OK;
}

void receive_packets(Raw_sockets_t* socks, Packet_t* packet_table, int table_size) {
    struct pollfd p_fds[4];
    p_fds[0].fd = socks->fd[TCP4_IN];
    p_fds[1].fd = socks->fd[TCP6_IN];
    p_fds[2].fd = socks->fd[UDP4_ICMP_IN];
    p_fds[3].fd = socks->fd[UDP6_ICMP_IN];

    for(int i = 0; i < 4; i++) {
        p_fds[i].events = POLLIN;
        p_fds[i].revents = 0;
    }

    unsigned char buffer[65536];
    struct sockaddr_storage src_addr;

    // Čekáme max 100ms, jestli se na některém socketu něco objeví
    int ret = poll(p_fds, 4, 100);
    if(ret <= 0)
        return;

    for(int i = 0; i < 4; i++) {
        // Pokud daný socket hlásí, že má data...
        if(p_fds[i].revents & POLLIN) {
            // ...čteme VŠECHNY pakety, které v tom socketu teď leží
            while(1) { // prisk:: zavisi na MSG_CONTWAIT
                socklen_t addr_len = sizeof(src_addr);
                int len = recvfrom(p_fds[i].fd, buffer, sizeof(buffer), MSG_DONTWAIT,
                                   (struct sockaddr*)&src_addr, &addr_len);

                // Pokud len < 0, znamená to, že buffer je prázdný (EAGAIN/EWOULDBLOCK)
                if(len < 0)
                    break;

                uint16_t res_port = 0;
                state_t res_status = ST_PENDING;
                proto_t res_proto;
                uint32_t res_ack = 0;

                // --- ANALÝZA (IPv4/IPv6 TCP) ---
                if(i == 0 || i == 1) {
                    res_proto = SCAN_TCP;
                    struct tcphdr* tcph;
                    if(i == 0) { // IPv4
                        if(len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr)))
                            continue;
                        struct iphdr* iph = (struct iphdr*)buffer;
                        tcph = (struct tcphdr*)(buffer + (iph->ihl * 4));
                    } else { // IPv6
                        if(len < (int)(sizeof(struct ip6_hdr) + sizeof(struct tcphdr)))
                            continue;
                        tcph = (struct tcphdr*)(buffer + sizeof(struct ip6_hdr));
                    }
                    res_port = ntohs(tcph->source);
                    res_ack = ntohl(tcph->ack_seq);
                    if(tcph->syn && tcph->ack)
                        res_status = ST_OPEN;
                    else if(tcph->rst)
                        res_status = ST_CLOSED;
                }
                // --- ANALÝZA (ICMP / UDP) ---
                else {
                    res_proto = SCAN_UDP;
                    if(i == 2) { // IPv4 ICMP response to UDP
                        if(len < (int)(sizeof(struct iphdr) + sizeof(struct icmphdr)))
                            continue;

                        struct iphdr* outer_ip = (struct iphdr*)buffer;
                        int outer_len = outer_ip->ihl * 4;
                        int offset = outer_len + (int)sizeof(struct icmphdr);

                        if(len < offset + (int)sizeof(struct iphdr))
                            continue;
                        struct iphdr* inner_ip = (struct iphdr*)(buffer + offset);
                        offset += inner_ip->ihl * 4;

                        if(len < offset + (int)sizeof(struct udphdr))
                            continue;
                        struct udphdr* old_udph = (struct udphdr*)(buffer + offset);
                        res_port = ntohs(old_udph->dest);
                    } else { // IPv6 ICMP response to UDP
                        int offset = (int)(sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
                        if(len < offset + (int)sizeof(struct udphdr))
                            continue;
                        struct udphdr* old_udph = (struct udphdr*)(buffer + offset);
                        res_port = ntohs(old_udph->dest);
                    }
                    res_status = ST_CLOSED;
                }

                // --- AKTUALIZACE TABULKY ---
                if(res_status != ST_PENDING) {
                    pthread_mutex_lock(&table_mutex);
                    for(int j = 0; j < table_size; j++) {
                        if(packet_table[j].port == res_port &&
                           packet_table[j].proto == res_proto &&
                           compare_ip((struct sockaddr*)&src_addr, (struct sockaddr*)&packet_table[j].target_addr)) {
                            if(res_proto == SCAN_TCP && res_ack != (uint32_t)(packet_table[j].seq_number + 1)) {
                                continue;
                            }
                            packet_table[j].status = res_status;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&table_mutex);
                }
            } // konec while(1) - vyčerpali jsme všechny pakety z jednoho socketu
        }
    }
}

int send_packets(Scanner_t* scanner, Destination_addresses_t* destination, Source_address_t* source, Raw_sockets_t* socks, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source, socks);
    int err = 0;
    for(size_t i = 0; i < destination->count; i++) {
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

    char send_buffer[4096];
    int packet_size = 0;
    uint16_t my_source_port = 12345; // todo::urcite musi zde byt nejaky volny port//musim napsat funkci, pro detekci meho portu
    uint16_t target_port;

    for(int i = 0; i < scanner->tcp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->tcp_ports), table, items, SCAN_TCP, i);
        // 2. Odešleme paket pomocí správného socketu
        if(items->family == AF_INET && sock4 != -1) {
            build_tcp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            // Pro IPv4 posíláme celý datagram (včetně námi vyrobené IP hlavičky)
            if(sendto(sock4, send_buffer, packet_size, 0,
                      (struct sockaddr*)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv4 selhalo");
            }
        } else if(items->family == AF_INET6 && sock6 != -1) { // todo:: fix -1 as magic num
            // Pro IPv6 posíláme jen TCP část (kernel si IP hlavičku dodá sám)
            build_tcp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            if(sendto(sock6, send_buffer, packet_size, 0,
                      (struct sockaddr*)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv6 selhalo");
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
            build_udp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);

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