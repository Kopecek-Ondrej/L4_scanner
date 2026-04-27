/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

// for POSIX APIs for clock_gettime() and CLOCK_MONOTONIC
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#define __FAVOR_BSD

// #include "parser.h"
#include "scanner.h"
#include "destination.h"
#include "error_code.h"
#include "source.h"
#include <libnet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h> // struct iphdr
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h> // for atomic operation in receiver thread
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;s

#define IPV4 4
#define IPV6 6
#define L2_HEADER_LEN 14
#define MAX_WAIT_MS 3000

#ifndef DEBUG_MACRO
#define DEBUG_MACRO(...) DEBUG_PRINT(__VA_ARGS__)
#endif

static size_t g_l2_header_len = L2_HEADER_LEN;
static uint32_t g_my_source_port = 0;

// lock for modifying Table_packet_t struct
pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

// helper struct for arguments for receiver_thread
// it better stay here
typedef struct {
    Cli_Parser_t* parser;
    Table_packet_t* table;
    _Atomic int err; // error handling from receiver_thread
} Receiver_args_t;

// Receiver thread
void* receiver_thread(void* arg) {
    Receiver_args_t* args = (Receiver_args_t*)arg;

    int err = receive_packets(args->parser, args->table);
    atomic_store(&args->err, err);

    return NULL;
}

int scan_destinations(Cli_Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
    pthread_t rx_thread;
    Receiver_args_t rx_args = {parser, table, 0};

    // we try to get an open port
    int dummy_tcp_fd = -1;
    int dummy_udp_fd = -1;
    g_my_source_port = get_available_source_port(&dummy_tcp_fd, &dummy_udp_fd);
    if(g_my_source_port == 0) {
        RETURN_ERROR(ERR_GET_PORT, "Erro while trying to get an open port");
    }

    // initialization of handle for terminating receiver_thread
    parser->pcap_handle = NULL;

    int err = pthread_create(&rx_thread, NULL, receiver_thread, &rx_args);
    if(err != 0) {
        clean_dummy_fd(&dummy_tcp_fd, &dummy_udp_fd);
        RETURN_ERROR(ERR_SYS_THREAD, "Failed to create receiver_thread: %s\n", strerror(err));
    }

    // erro handling from receiver thread
    int rx_err;

    // wait a while for receiver thread to prepare filters
    // wait or expect an error
    // receiver_thread sets handle
    int waited_ms = 0;
    while(parser->pcap_handle == NULL && (waited_ms < MAX_WAIT_MS)) {
        rx_err = atomic_load(&rx_args.err);
        if(rx_err != EXIT_OK) {
            pthread_join(rx_thread, NULL); // most likely wont fail
            clean_dummy_fd(&dummy_tcp_fd, &dummy_udp_fd);
            return rx_err;
        }

        usleep(1000);
        waited_ms++;
    }

    if(parser->pcap_handle == NULL) {
        pthread_join(rx_thread, NULL);
        clean_dummy_fd(&dummy_tcp_fd, &dummy_udp_fd);
        RETURN_ERROR(ERR_PCAP, "Receiver thread failed to initialize pcap in interface: %s", parser->interface);
    }

    err = send_packets(parser, destination, source, table);
    if(err != EXIT_OK) {
        if(parser->pcap_handle != NULL) {
            pcap_breakloop(parser->pcap_handle);
        }
        pthread_join(rx_thread, NULL);
        clean_dummy_fd(&dummy_tcp_fd, &dummy_udp_fd);
        return err;
    }

    bool finished = false;

    while(!finished) {
        finished = true;

        pthread_mutex_lock(&table_mutex);

        for(int i = 0; i < table->size; i++) {
            Packet_t* pckt = &table->packets[i];

            // skip for ST_OPEN, ST_FILTERED, ST_CLOSED
            if(pckt->status != ST_PENDING) {
                continue;
            }

            finished = false;
            // check for timeout on each packet and evaluate
            long elapsed_ms = get_elapsed_ms(pckt->last_sent);
            if(elapsed_ms >= parser->timeout) {
                if(pckt->tries == 1) {
                    pckt->tries = 2;
                    // calc new ttime
                    clock_gettime(CLOCK_MONOTONIC, &pckt->last_sent);

                    // send again only TCP packets
                    if(pckt->proto == SCAN_TCP) {
                        send_single_tcp_packet(pckt, parser);
                    }
                } else if(pckt->tries == 2) {
                    // default evaluation after timeout
                    if(pckt->proto == SCAN_TCP) {
                        pckt->status = ST_FILTERED;
                    } // UDP packets had doubled timeout
                    else if(pckt->proto == SCAN_UDP) {
                        pckt->status = ST_OPEN;
                    }
                }
            }
        }
        pthread_mutex_unlock(&table_mutex);
        // give time for other thread
        if(!finished) {
            usleep(1000);
        }
    }
    // signal to receiver_thread to stop
    if(parser->pcap_handle != NULL) {
        pcap_breakloop(parser->pcap_handle);
    }

    clean_dummy_fd(&dummy_tcp_fd, &dummy_udp_fd);

    pthread_join(rx_thread, NULL);

    return EXIT_OK;
}

int receive_packets(Cli_Parser_t* parser, Table_packet_t* table) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;

    // promiscuit mode turned off to filter unwanted traffic
    handle = pcap_open_live(parser->interface, BUFSIZ, 0, 100, errbuf);
    if(handle == NULL) {
        RETURN_ERROR(ERR_PCAP, "Unable to open %s: %s\n", parser->interface, errbuf);
    }

    // determine type of link-layer
    int header_type = pcap_datalink(handle);
    switch(header_type) {
    case DLT_EN10MB: // for IEEE802.3 Ethernet
        g_l2_header_len = 14;
        break;
    case DLT_LINUX_SLL:
        g_l2_header_len = 16;
        break;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:
        g_l2_header_len = 20;
        break;
#endif
    case DLT_NULL:
        g_l2_header_len = 4;
        break;
    case DLT_RAW:
        g_l2_header_len = 0;
        break;
    default:
        g_l2_header_len = 14;
        break;
    }

    // setting up filter only for ports icmp and icmp6
    int err = setup_pcap_filter(handle, g_my_source_port);
    if(err != EXIT_OK) {
        pcap_close(handle);
        parser->pcap_handle = NULL;
        return err;
    }

    // signal readiness to sender only after capture is fully configured
    parser->pcap_handle = handle;

    //-1 ... runs infinitely and waits for termination from another thread (handle)
    // packet_handler: function for evaluation
    err = pcap_loop(handle, -1, packet_handler, (unsigned char*)table);
    if(err == -1) {
        pcap_close(handle);
        parser->pcap_handle = NULL;
        RETURN_ERROR(ERR_PCAP, "Error in pcap_loop: %s\n", pcap_geterr(handle));
    }
    //-2 for pcap_breakloop() 0 for natural end

    pcap_close(handle);
    parser->pcap_handle = NULL;
    return EXIT_OK;
}

int send_packets(Cli_Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, parser, destination, source);

    int err = 0;

    for(size_t i = 0; i < destination->count; i++) {
        Resolved_address_t* item = &(destination->items[i]);

        if(parser->tcp_use) {
            err = send_with_tcp(item, parser, source, table);
            if(err != EXIT_OK) {
                free_destination_addresses(destination);
                return err;
            }
        }

        if(parser->udp_use) {
            err = send_with_udp(item, parser, source, table);
            if(err != EXIT_OK) {
                free_destination_addresses(destination);
                return err;
            }
        }
    }

    if((parser->udp_use == false) && (parser->tcp_use == false)) {
        free_destination_addresses(destination);
        printf("udp: %d, tcp: %d", parser->udp_use, parser->tcp_use);
        RETURN_ERROR(ERR_CLI_ARG, "No port has been selected");
    }

    return EXIT_OK;
}

int send_single_tcp_packet(Packet_t* packet, Cli_Parser_t* parser) {
    // here init libnet_t
    // and other stuff of that kind
    int err = 0;
    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag = 0;
    libnet_ptag_t ip_tag = 0;

    int libnet_mode = (packet->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);
    if(lib == NULL) {
        RETURN_ERROR(ERR_SYS_LIBNET_INIT, "libnet_init() failed: %s\n", errbuf);
    }

    err = dispatch_tcp_packet(lib, packet->family, &packet->src_addr, &packet->dst_addr,
                              packet->src_port, packet->dst_port, &tcp_tag, &ip_tag, &(packet->seq_number));
    if(err != 0) {
        libnet_destroy(lib);
        return err;
    }

    libnet_destroy(lib);
    return EXIT_OK;
}

int dispatch_udp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* udp_tag, libnet_ptag_t* ip_tag) {
    if(family == AF_INET) {
        // udp head assemble
        *udp_tag = libnet_build_udp(src_prt, dst_prt, LIBNET_UDP_H, 0,
                                    NULL, 0, lib, *udp_tag);

        // Ipv4 head assemble
        *ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H, 0, 242, 0, 64, IPPROTO_UDP, 0,
                                    source->addr4, dest->addr.raddr4, NULL, 0, lib, *ip_tag);

    } else { // AF_INET6

        *udp_tag = libnet_build_udp(src_prt, dst_prt, LIBNET_UDP_H, 0,
                                    NULL, 0, lib, *udp_tag);

        *ip_tag = libnet_build_ipv6(0, 0, LIBNET_UDP_H, IPPROTO_UDP, 64,
                                    source->addr6, dest->addr.raddr6, NULL, 0, lib, *ip_tag);
    }

    if(*udp_tag == -1 || *ip_tag == -1) {
        RETURN_ERROR(ERR_SYS_LIBNET_PACKET, "Error building UDP packet: %s\n", libnet_geterror(lib));
    }

    if(libnet_write(lib) == -1) {
        RETURN_ERROR(ERR_SYS_LIBNET_PACKET, "Write error (UDP): %s\n", libnet_geterror(lib));
    }

    return EXIT_OK;
}

int dispatch_tcp_packet(libnet_t* lib, int family, Source_address_t* source,
                        Resolved_address_t* dest, uint16_t src_prt, uint16_t dst_prt,
                        libnet_ptag_t* tcp_tag, libnet_ptag_t* ip_tag, uint32_t* packet_tcp_seq) {
    if(family == AF_INET) {
        // TCP head
        *tcp_tag = libnet_build_tcp(src_prt, dst_prt, *packet_tcp_seq, 0, TH_SYN, 32767, 0, 0,
                                    LIBNET_TCP_H, NULL, 0, lib, *tcp_tag);

        // ipv4 head
        *ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0, 242, 0, 64, IPPROTO_TCP, 0,
                                    source->addr4, dest->addr.raddr4, NULL, 0, lib, *ip_tag);
    } else {
        // tcp head
        *tcp_tag = libnet_build_tcp(src_prt, dst_prt, *packet_tcp_seq, 0, TH_SYN, 32767, 0, 0,
                                    LIBNET_TCP_H, NULL, 0, lib, *tcp_tag);
        // ipv6 head4
        *ip_tag = libnet_build_ipv6(0, 0, LIBNET_TCP_H, IPPROTO_TCP, 64,
                                    source->addr6, dest->addr.raddr6, NULL, 0, lib, *ip_tag);
    }

    if(*tcp_tag == -1 || *ip_tag == -1) {
        RETURN_ERROR(ERR_SYS_LIBNET_PACKET, "Error building TCP packet: %s\n", libnet_geterror(lib));
    }

    if(libnet_write(lib) == -1) {
        RETURN_ERROR(ERR_SYS_LIBNET_PACKET, "Write error: %s\n", libnet_geterror(lib));
    }

    return EXIT_OK;
}

int send_with_tcp(Resolved_address_t* dst_addr, Cli_Parser_t* parser, Source_address_t* src_addr, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, dst_addr, parser, src_addr, table);

    uint16_t src_port = g_my_source_port;
    int target_port; // type int for receiving error codes
    int err = 0;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag = 0;
    libnet_ptag_t ip_tag = 0;
    uint32_t packet_tcp_seq = 0;

    int libnet_mode = (dst_addr->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);
    if(lib == NULL) {
        RETURN_ERROR(ERR_SYS_LIBNET_INIT, "libnet_init() failed: %s\n", errbuf);
    }

    for(int i = 0; i < parser->tcp_ports.port_cnt; i++) {
        // generates unique sequential number
        packet_tcp_seq = libnet_get_prand(LIBNET_PRu32);

        target_port = get_port(&(parser->tcp_ports), table, dst_addr, SCAN_TCP, i, src_port, src_addr, &packet_tcp_seq);
        if(target_port < 0) {
            libnet_destroy(lib);
            return target_port; // represents error code
        }

        err = dispatch_tcp_packet(lib, dst_addr->family, src_addr, dst_addr, src_port,
                                  target_port, &tcp_tag, &ip_tag, &packet_tcp_seq);
        if(err != EXIT_OK) {
            libnet_destroy(lib);
            return err;
        }
    }
    libnet_destroy(lib);
    return EXIT_OK;
}

int send_with_udp(Resolved_address_t* dst_addr, Cli_Parser_t* parser, Source_address_t* src_addr, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, dst_addr, parser, src_addr, table);

    uint16_t src_port = g_my_source_port;
    int target_port; // int for receiving error codes
    int err = 0;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t udp_tag = 0;
    libnet_ptag_t ip_tag = 0;
    uint32_t packet_udp_seq = 0;

    int libnet_mode = (dst_addr->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);
    if(lib == NULL) {
        RETURN_ERROR(ERR_SYS_LIBNET_INIT, "libnet_init() failed: %s\n", errbuf);
    }

    // send packet to all ports for a give dst_addr
    for(int i = 0; i < parser->udp_ports.port_cnt; i++) {
        packet_udp_seq = libnet_get_prand(LIBNET_PRu32);

        target_port = get_port(&(parser->udp_ports), table, dst_addr, SCAN_UDP, i, src_port, src_addr, &packet_udp_seq);
        if(target_port < 0) {
            libnet_destroy(lib);
            return target_port; // represents error code
        }

        err = dispatch_udp_packet(lib, dst_addr->family, src_addr, dst_addr, src_port, target_port, &udp_tag, &ip_tag);
        if(err != EXIT_OK) {
            libnet_destroy(lib);
            return err;
        }
        // DEBUG_PRINT("sent syn PORT: %d, TARGET: %s", target_port, dst_addr->);
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

int get_port(Ports_t* ports, Table_packet_t* table, Resolved_address_t* raddr,
             proto_t protocol, int iter, uint16_t src_port, Source_address_t* src_addr, uint32_t* packet_tcp_seq) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, ports, table, raddr);

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
            RETURN_ERROR(ERR_CLI_ARG, "Invalid port list"); // return negative int
        }
        break;
    }

    pthread_mutex_lock(&table_mutex);

    if(table->next_seq >= table->size) {
        pthread_mutex_unlock(&table_mutex);
        RETURN_ERROR(ERR_SYS_MEM_ALLOC, "Packet table overflow"); // return negative int
    }

    int idx = table->next_seq++;
    Packet_t* p = &table->packets[idx];

    p->seq_number = *packet_tcp_seq;
    p->tries = 1;
    p->status = ST_PENDING;
    p->dst_port = port;
    p->src_port = src_port;
    p->proto = protocol;
    // p->addr_len = raddr->addr_len;
    p->family = raddr->family;
    memcpy(&p->dst_addr, raddr, sizeof(Resolved_address_t));
    memcpy(&p->src_addr, src_addr, sizeof(Source_address_t));
    clock_gettime(CLOCK_MONOTONIC, &(p->last_sent));

    pthread_mutex_unlock(&table_mutex);

    return port;
}

int read_next_port(char* s, int pos, int* port) {
    int value = 0;

    while(s[pos] != '\0' && s[pos] != ',') {
        value = value * 10 + (s[pos] - '0');
        pos++;
    }

    *port = value;
    if(s[pos] == ',')
        pos++; // skip comma

    return pos;
}

long get_elapsed_ms(struct timespec start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long seconds = now.tv_sec - start.tv_sec;
    long nanoseconds = now.tv_nsec - start.tv_nsec;

    return (seconds * 1000) + (nanoseconds / 1000000);
}
int setup_pcap_filter(pcap_t* handle, uint32_t my_source_port) {
    char filter_str[128];
    // Vytvoříme statický filtr na náš zdrojový port a ICMP
    snprintf(filter_str, sizeof(filter_str), "(dst port %u) or icmp or icmp6", my_source_port);

    struct bpf_program fp;
    int result = EXIT_OK;

    if(pcap_compile(handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Failed to compile pcap_filter: %s\n", pcap_geterr(handle));
        return ERR_PCAP;
    }

    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set pcap_filter: %s\n", pcap_geterr(handle));
        result = ERR_PCAP;
    }

    pcap_freecode(&fp);
    return result;
}

static bool match_reply_to_probe(const Packet_t* p,
                                 int family,
                                 const struct in_addr* src4,
                                 const struct in6_addr* src6,
                                 uint16_t rx_src_port,
                                 uint16_t rx_dst_port) {
    if(p->family != family) {
        return false;
    }

    // reply tuple must be reversed against sent probe
    if(p->dst_port != rx_src_port || p->src_port != rx_dst_port) {
        return false;
    }

    if(family == AF_INET) {
        return p->dst_addr.addr.raddr4 == src4->s_addr;
    }

    if(family == AF_INET6) {
        return memcmp(&p->dst_addr.addr.raddr6, src6, sizeof(struct in6_addr)) == 0;
    }

    return false;
}

static void apply_icmp_udp_closed(Table_packet_t* table, const Parsed_packet_t* pp) {
    if(!pp->icmp_udp_unreach) {
        return;
    }

    for(int i = 0; i < table->size; i++) {
        Packet_t* p = &table->packets[i];
        if(p->proto != SCAN_UDP) {
            continue;
        }

        if(pp->inner_family == AF_INET) {
            if(p->family == AF_INET &&
               p->dst_port == pp->inner_dst_port &&
               p->dst_addr.addr.raddr4 == pp->inner_dst4.s_addr) {
                p->status = ST_CLOSED;
            }
        } else if(pp->inner_family == AF_INET6) {
            if(p->family == AF_INET6 &&
               p->dst_port == pp->inner_dst_port &&
               memcmp(&p->dst_addr.addr.raddr6, &pp->inner_dst6, sizeof(struct in6_addr)) == 0) {
                p->status = ST_CLOSED;
            }
        }
    }
}

static bool parse_ipv4_packet(const unsigned char* packet, uint32_t caplen, Parsed_packet_t* pp) {
    if(caplen < g_l2_header_len + sizeof(struct ip)) {
        return false;
    }

    const struct ip* ip4 = (const struct ip*)(packet + g_l2_header_len);
    int ip_hl = ip4->ip_hl * 4;
    if(ip_hl < (int)sizeof(struct ip) || caplen < g_l2_header_len + (size_t)ip_hl) {
        return false;
    }

    pp->family = AF_INET;
    pp->l4_proto = ip4->ip_p;
    pp->src4 = ip4->ip_src;
    pp->dst4 = ip4->ip_dst;

    {
        char src_ip[INET_ADDRSTRLEN] = {0};
        char dst_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &pp->src4, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pp->dst4, dst_ip, sizeof(dst_ip));
    }

    const unsigned char* l4 = packet + g_l2_header_len + (size_t)ip_hl;
    size_t l4_len = caplen - (g_l2_header_len + (size_t)ip_hl);

    if(pp->l4_proto == IPPROTO_TCP) {
        if(l4_len < sizeof(struct tcphdr)) {
            return false;
        }
        const struct tcphdr* tcp = (const struct tcphdr*)l4;
        pp->src_port = ntohs(tcp->th_sport);
        pp->dst_port = ntohs(tcp->th_dport);
        pp->tcp_rst = ((tcp->th_flags & TH_RST) != 0);
        pp->tcp_syn_ack = ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK));
        pp->has_ports = true;
        return true;
    }

    if(pp->l4_proto == IPPROTO_UDP) {
        if(l4_len < sizeof(struct udphdr)) {
            return false;
        }
        const struct udphdr* udp = (const struct udphdr*)l4;
        pp->src_port = ntohs(udp->uh_sport);
        pp->dst_port = ntohs(udp->uh_dport);
        pp->has_ports = true;
        return true;
    }

    if(pp->l4_proto == IPPROTO_ICMP) {
        if(l4_len < ICMP_MINLEN) {
            return false;
        }

        const struct icmp* icmp4 = (const struct icmp*)l4;
        if(icmp4->icmp_type == ICMP_UNREACH && icmp4->icmp_code == ICMP_UNREACH_PORT) {
            // ICMPv4 error payload starts after fixed 8-byte ICMP header.
            const unsigned char* inner = l4 + ICMP_MINLEN;
            size_t inner_len = l4_len - ICMP_MINLEN;
            // is there enough for basic ipv4 head?
            if(inner_len >= sizeof(struct ip)) {
                const struct ip* orig4 = (const struct ip*)inner;
                int orig_hl = orig4->ip_hl * 4;

                if(orig_hl >= (int)sizeof(struct ip) &&
                   inner_len >= (size_t)orig_hl + sizeof(struct udphdr) &&
                   orig4->ip_p == IPPROTO_UDP) {
                    const struct udphdr* orig_udp = (const struct udphdr*)(inner + (size_t)orig_hl);
                    pp->icmp_udp_unreach = true;
                    pp->inner_family = AF_INET;
                    pp->inner_dst_port = ntohs(orig_udp->uh_dport);
                    pp->inner_dst4 = orig4->ip_dst;
                }
            }
        }
        return true;
    }

    return true;
}

static bool parse_ipv6_packet(const unsigned char* packet, uint32_t caplen, Parsed_packet_t* pp) {
    if(caplen < g_l2_header_len + sizeof(struct ip6_hdr)) {
        return false;
    }

    const struct ip6_hdr* ip6 = (const struct ip6_hdr*)(packet + g_l2_header_len);
    size_t l4_off = g_l2_header_len + sizeof(struct ip6_hdr);
    if(caplen < l4_off) {
        return false;
    }

    pp->family = AF_INET6;
    pp->l4_proto = ip6->ip6_nxt; // simplified: no ext headers
    pp->src6 = ip6->ip6_src;
    pp->dst6 = ip6->ip6_dst;

    {
        char src_ip[INET6_ADDRSTRLEN] = {0};
        char dst_ip[INET6_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET6, &pp->src6, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &pp->dst6, dst_ip, sizeof(dst_ip));
    }

    const unsigned char* l4 = packet + l4_off;
    size_t l4_len = caplen - l4_off;

    if(pp->l4_proto == IPPROTO_TCP) {
        if(l4_len < sizeof(struct tcphdr)) {
            return false;
        }
        const struct tcphdr* tcp = (const struct tcphdr*)l4;
        pp->src_port = ntohs(tcp->th_sport);
        pp->dst_port = ntohs(tcp->th_dport);
        pp->tcp_rst = ((tcp->th_flags & TH_RST) != 0);
        pp->tcp_syn_ack = ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK));
        pp->has_ports = true;
        return true;
    }

    if(pp->l4_proto == IPPROTO_UDP) {
        if(l4_len < sizeof(struct udphdr)) {
            return false;
        }
        const struct udphdr* udp = (const struct udphdr*)l4;
        pp->src_port = ntohs(udp->uh_sport);
        pp->dst_port = ntohs(udp->uh_dport);
        pp->has_ports = true;
        return true;
    }

    if(pp->l4_proto == IPPROTO_ICMPV6) {
        if(l4_len < sizeof(struct icmp6_hdr)) {
            return false;
        }

        const struct icmp6_hdr* ic6 = (const struct icmp6_hdr*)l4;
        if(ic6->icmp6_type == ICMP6_DST_UNREACH && ic6->icmp6_code == ICMP6_DST_UNREACH_NOPORT) {
            const unsigned char* inner = l4 + sizeof(struct icmp6_hdr);
            size_t inner_len = l4_len - sizeof(struct icmp6_hdr);
            if(inner_len >= sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
                const struct ip6_hdr* orig6 = (const struct ip6_hdr*)inner;
                if(orig6->ip6_nxt == IPPROTO_UDP) {
                    const struct udphdr* orig_udp = (const struct udphdr*)(inner + sizeof(struct ip6_hdr));
                    pp->icmp_udp_unreach = true;
                    pp->inner_family = AF_INET6;
                    pp->inner_dst_port = ntohs(orig_udp->uh_dport);
                    pp->inner_dst6 = orig6->ip6_dst;
                }
            }
        }
        return true;
    }

    return true;
}

void packet_handler(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {
    if(args == NULL || header == NULL || packet == NULL) {
        return;
    }

    if(header->caplen < g_l2_header_len + 1u) {
        return;
    }

    Table_packet_t* table = (Table_packet_t*)args;
    Parsed_packet_t pp;
    memset(&pp, 0, sizeof(pp));
    pp.family = AF_UNSPEC;

    // detect IP version from first nibble
    const unsigned char* ip_start = packet + g_l2_header_len;
    uint8_t ip_version = (uint8_t)((ip_start[0] >> 4) & 0x0F);

    bool ok = false;
    if(ip_version == 4) {
        ok = parse_ipv4_packet(packet, header->caplen, &pp);
    } else if(ip_version == 6) {
        ok = parse_ipv6_packet(packet, header->caplen, &pp);
    } else {
        return;
    }

    if(!ok) {
        return;
    }

    pthread_mutex_lock(&table_mutex);

    // ICMP unreachable for UDP => CLOSED
    apply_icmp_udp_closed(table, &pp);

    // TCP/UDP direct replies
    if(pp.has_ports) {
        for(int i = 0; i < table->size; i++) {
            Packet_t* p = &table->packets[i];

            if(!match_reply_to_probe(p, pp.family, &pp.src4, &pp.src6, pp.src_port, pp.dst_port)) {
                continue;
            }

            if(p->proto == SCAN_TCP && pp.l4_proto == IPPROTO_TCP) {
                if(pp.tcp_rst) {
                    p->status = ST_CLOSED;
                } else if(pp.tcp_syn_ack) {
                    p->status = ST_OPEN;
                }
            } else if(p->proto == SCAN_UDP && pp.l4_proto == IPPROTO_UDP) {
                p->status = ST_OPEN;
            }
        }
    }

    pthread_mutex_unlock(&table_mutex);
}