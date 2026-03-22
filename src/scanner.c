// #include "parser.h"
#include "scanner.h"
#include "address.h"
#include "error_code.h"
#include "protocol.h"
// #include <libpcap.h>
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

// Zámek pro bezpečnou práci s tabulkou packetů
pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

// Pomocná struktura pro předání argumentů do Vlákna B
typedef struct {
    Parser_t *parser;
    Destination_addresses_t *dest;
    Table_packet_t *table;
} Receiver_args_t;

// --- VLÁKNO B: PŘÍJEM PACKETŮ ---
void* receiver_thread(void* arg) {
    Receiver_args_t *args = (Receiver_args_t *)arg;
    
    // Spuštění tvé funkce, která uvnitř volá pcap_loop()
    receive_packets(args->parser, args->dest, args->table);
    
    return NULL;
}

int scan_destinations(Parser_t *parser, Destination_addresses_t *destination, Source_address_t *source, Table_packet_t *table) {
    pthread_t rx_thread;
    Receiver_args_t rx_args = { parser, destination, table };

    parser->pcap_handle = NULL;

    // 1. Vytvoření Vlákna B (Příjem packetů)
    if (pthread_create(&rx_thread, NULL, receiver_thread, &rx_args) != 0) {
        fprintf(stderr, "Chyba při vytváření přijímacího vlákna.\n");
        return -1;
    }

    while(parser->pcap_handle == NULL){
        usleep(1000);
    }

    // 2. Odeslání všech packetů (Vlákno A)
    send_packets(parser, destination, source, table);

    // 3. Kontrolní smyčka (Vlákno A)
    bool all_done = false;
    struct timespec now;

    while (!all_done) {
        all_done = true; // Předpokládáme, že je hotovo
        clock_gettime(CLOCK_MONOTONIC, &now);

        // ZAMKNUTÍ TABULKY: Exkluzivní přístup pro Vlákno A
        pthread_mutex_lock(&table_mutex);

        for (int i = 0; i < table->size; i++) {
            Packet_t *pckt = &table->packets[i];

            if (pckt->status == ST_PENDING) {
                all_done = false; // Našli jsme nedořešený packet, skenování pokračuje

                // Výpočet uplynulého času
                long elapsed_ms = (now.tv_sec - pckt->last_sent.tv_sec) * 1000 + 
                                  (now.tv_nsec - pckt->last_sent.tv_nsec) / 1000000;//todo:: use function elapsed time

                if (elapsed_ms >= parser->timeout) {
                    if (pckt->tries == 1) {
                        // PRVNÍ TIMEOUT -> Retransmise
                        pckt->tries = 2;
                        clock_gettime(CLOCK_MONOTONIC, &pckt->last_sent); // Aktualizace času odeslání

                        if (pckt->proto == SCAN_TCP) { // Předpokládám tvé makro pro TCP
                            send_single_tcp_packet(pckt, parser);
                        } else if (pckt->proto == SCAN_UDP) {
                            pckt->status = ST_OPEN; // Ticho u UDP znamená OPEN
                        }
                    } 
                    else if (pckt->tries == 2) {
                        // DRUHÝ TIMEOUT -> Finální vyhodnocení
                        if (pckt->proto == SCAN_TCP) {
                            pckt->status = ST_FILTERED;
                        }
                    }
                }
            }
        }
        
        // ODEMKNUTÍ TABULKY: Vlákno B (packet_handler) nyní může zapisovat
        pthread_mutex_unlock(&table_mutex);

        // Aby cyklus neběžel na 100% CPU, chvíli počkáme
        if (!all_done) {
            usleep(10000); // 10 ms
        }
    }

    // 4. Všechny packety jsou vyřešeny (žádný není ST_PENDING)
    // Ukončení pcap_loop ve Vláknu B
    if (parser->pcap_handle != NULL) {
        pcap_breakloop(parser->pcap_handle);
    }

    // 5. Počkáme na korektní ukončení Vlákna B
    pthread_join(rx_thread, NULL);
    return 0; //todo:: edit
}

/**
 * Hlavní funkce pro příjem na definovaném rozhraní.
 */
int receive_packets(Parser_t *parser, Destination_addresses_t *dest, Table_packet_t* table) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 1. Otevření síťového rozhraní (promiskuitní mód, 1s timeout)
    handle = pcap_open_live(parser->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Nelze otevřít zařízení %s: %s\n", parser->interface, errbuf);
        return -1;
    }
    //handler for termination of rx_thread
    parser->pcap_handle = handle;

    //setting up filter only for IP addressed in dest
    if (setup_pcap_filter(handle, dest) != 0) {
        fprintf(stderr, "Chyba při nastavování BPF filtru.\n");
        pcap_close(handle);
        return -1;
    }

    DEBUG_PRINT("nasloubha na : %s s aktiv IP filtrem", parser->interface);

    // 3. Spuštění smyčky pro příjem
    // Parametr -1 znamená "běž nekonečně", 0 znamená "zpracuj vše co je ve frontě a skonči"
    // packet_handler je naše funkce, NULL jsou volitelná uživatelská data (args)
    int err = pcap_loop(handle, -1, packet_handler, (u_char*)table);
    if ( err == -1) {
        fprintf(stderr, "Chyba v pcap_loop: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }else if(err == -2 || err == 0){ //-2 for pcap_breakloop() 0 for natural end
        return EXIT_OK;
    }

    // 4. Úklid (pokud smyčka někdy skončí)
    pcap_close(handle);
    return 0;
}

int send_packets(Parser_t* parser, Destination_addresses_t* destination, Source_address_t* source, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, parser, destination, source);
    int err = 0;
    DEBUG_PRINT("dest cnt: %ld", destination->count);
    for(size_t i = 0; i < destination->count; i++) {
        // todo:: funkce ktera bude dava validni vystupni port
        Resolved_address_t* item = &(destination->items[i]);

        if(parser->tcp_use) {
            err = send_with_tcp(item, parser, source, table);
            if(err != EXIT_OK)
                return err;
        }

        if(parser->udp_use) {
            err = send_with_udp(item, parser, source, table);
            if(err != EXIT_OK)
                return err;
        }
    }

    if((parser->udp_use == false) && (parser->tcp_use == false)) {
        free_destination_addresses(destination);
        DEBUG_PRINT("udp: %d, tcp: %d", parser->udp_use, parser->tcp_use);
        printf("udp: %d, tcp: %d", parser->udp_use, parser->tcp_use);
        RETURN_ERROR(ERR_CLI_ARG, "No port has been selected");
    }

    return EXIT_OK;
}

int send_single_tcp_packet(Packet_t * packet, Parser_t *parser){
    //here init libnet_t
    //and other stuff of that kind
    // int err = 0;
    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag = 0;
    libnet_ptag_t ip_tag = 0;
    // packet->src_port = 12345; //todo:: pridat funkci, ktera vezme default port a podiva se, zda je port free.
    int libnet_mode = (packet->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);

    if(lib == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }


    if(dispatch_tcp_packet(lib, packet->family, &packet->src_addr, &packet->dst_addr, packet->src_port, packet->dst_port, &tcp_tag, &ip_tag) != 0){
        fprintf(stderr, "error"); //todo edit error
    }

    DEBUG_PRINT("second try for packet PORT: %d", packet->dst_port);

    libnet_destroy(lib);
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
#ifdef DEBUG
    char target_ip[INET6_ADDRSTRLEN] = {0};
    if(family == AF_INET) {
        struct in_addr addr4 = {.s_addr = dest->addr.raddr4};
        inet_ntop(AF_INET, &addr4, target_ip, sizeof(target_ip));
    } else {
        struct in6_addr addr6;
        memcpy(&addr6, &dest->addr.raddr6, sizeof(addr6));
        inet_ntop(AF_INET6, &addr6, target_ip, sizeof(target_ip));
    }
    DEBUG_PRINT("Sent UDP packet to PORT: %u, TARGET: %s", (unsigned)dst_prt, target_ip);
#endif
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

#ifdef DEBUG
    char target_ip[INET6_ADDRSTRLEN] = {0};
    if(family == AF_INET) {
        struct in_addr addr4 = {.s_addr = dest->addr.raddr4};
        inet_ntop(AF_INET, &addr4, target_ip, sizeof(target_ip));
    } else {
        struct in6_addr addr6;
        memcpy(&addr6, &dest->addr.raddr6, sizeof(addr6));
        inet_ntop(AF_INET6, &addr6, target_ip, sizeof(target_ip));
    }
    DEBUG_PRINT("Sent TCP packet to PORT: %u, TARGET: %s", (unsigned)dst_prt, target_ip);
#endif

    return 0;
}

int send_with_tcp(Resolved_address_t* item, Parser_t* parser, Source_address_t* src_addr, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, item, parser, src_addr, table);

    uint16_t src_port = 12345; // todo::urcite musi zde byt nejaky volny port//musim napsat funkci, pro detekci meho portu
    uint16_t target_port;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t tcp_tag = 0;
    libnet_ptag_t ip_tag = 0;

    int libnet_mode = (item->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);

    if(lib == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    for(int i = 0; i < parser->tcp_ports.port_cnt; i++) {
        target_port = get_port(&(parser->tcp_ports), table, item, SCAN_TCP, i, src_port, src_addr);

        if(dispatch_tcp_packet(lib, item->family, src_addr, item, src_port, target_port, &tcp_tag, &ip_tag) == 0) {
            // DEBUG_PRINT("sent syn PORT: %d, TARGET: %s", target_port, item->);

        } else {
            // if sending fails we continue
            fprintf(stderr, "Failed to dispatch YCP packet to port: %d\n", target_port);
        }
    }
    libnet_destroy(lib);
    return EXIT_OK;
}

int send_with_udp(Resolved_address_t* raddr, Parser_t* parser, Source_address_t* src_addr, Table_packet_t* table) {
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, raddr, parser, src_addr, table);

    uint16_t src_port = 54321; // it has been recommended to keep this one fixed
    uint16_t target_port;

    libnet_t* lib = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t udp_tag = 0;
    libnet_ptag_t ip_tag = 0;

    int libnet_mode = (raddr->family == AF_INET) ? LIBNET_RAW4 : LIBNET_RAW6;
    lib = libnet_init(libnet_mode, parser->interface, errbuf);

    if(lib == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    for(int i = 0; i < parser->udp_ports.port_cnt; i++) {
        target_port = get_port(&(parser->udp_ports), table, raddr, SCAN_UDP, i, src_port, src_addr);

        if(dispatch_udp_packet(lib, raddr->family, src_addr, raddr, src_port, target_port, &udp_tag, &ip_tag) == 0) {
            // DEBUG_PRINT("sent syn PORT: %d, TARGET: %s", target_port, raddr->);

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

int get_port(Ports_t* ports, Table_packet_t* table, Resolved_address_t* raddr, proto_t protocol, int iter, uint16_t src_port, Source_address_t* src_addr) {
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
    p->dst_port = port;
    p->src_port = src_port;
    p->proto = protocol;
    // p->addr_len = raddr->addr_len;
    p->family = raddr->family;
    memcpy(&p->dst_addr, raddr, sizeof(Resolved_address_t));
    memcpy(&p->src_addr, src_addr, sizeof(Source_address_t));
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

int setup_pcap_filter(pcap_t *handle, Destination_addresses_t *dest) {
    if (dest->count == 0) return 0;

    // 1. Odhadneme velikost bufferu pro filtr (cca 50 bytů na jednu IP + operátory)
    size_t buffer_size = dest->count * 64; 
    char *filter_str = malloc(buffer_size);
    if (!filter_str) return -1;
    
    filter_str[0] = '\0';
    char addr_buf[INET6_ADDRSTRLEN];

    // 2. Projdeme všechny uložené adresy a spojíme je pomocí "or"
    for (size_t i = 0; i < dest->count; i++) {
        Resolved_address_t *r = &dest->items[i];
        const char *ip_str = NULL;

        if (r->family == AF_INET) {
            ip_str = inet_ntop(AF_INET, &r->addr.raddr4, addr_buf, sizeof(addr_buf));
        } else if (r->family == AF_INET6) {
            ip_str = inet_ntop(AF_INET6, &r->addr.raddr6, addr_buf, sizeof(addr_buf));
        }

        if (ip_str) {
            // Pokud to není první adresa, přidáme " or "
            if (i > 0) strcat(filter_str, " or ");
            
            strcat(filter_str, "src host ");
            strcat(filter_str, ip_str);
        }
    }

    // 3. Kompilace a aplikace filtru
    struct bpf_program fp;
    int result = 0;

    if (pcap_compile(handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Chyba kompilace: %s\n", pcap_geterr(handle));
        result = -1;
    } else {
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Chyba nastavení: %s\n", pcap_geterr(handle));
            result = -1;
        }
        pcap_freecode(&fp); // Uvolnění vnitřních struktur filtru
    }

    free(filter_str);
    return result;
}

static bool packet_matches_target(const Packet_t *pckt, int family,
                                  const struct in_addr *src_ip4,
                                  const struct in6_addr *src_ip6,
                                  uint16_t src_port,
                                  uint16_t dst_port) {
    if (pckt->family != family) {
        return false;
    }

    if (pckt->dst_port != src_port || pckt->src_port != dst_port) {
        return false;
    }

    if (family == AF_INET) {
        return pckt->dst_addr.addr.raddr4 == src_ip4->s_addr;
    }

    if (family == AF_INET6) {
        return memcmp(&pckt->dst_addr.addr.raddr6, src_ip6, sizeof(struct in6_addr)) == 0;
    }

    return false;
}


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    const size_t l2_hdr_len = 14;
    if (header->caplen < l2_hdr_len + 1) {
        return; // Packet is too short/corrupted, ignore it
    }

    Table_packet_t *table = (Table_packet_t *)args;
    
    // 1. Přeskočíme Ethernet hlavičku (14 bajtů)
    struct ip *ip_hdr = (struct ip *)(packet + l2_hdr_len);
    int ip_version = ip_hdr->ip_v;
    
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    bool is_rst = false;
    bool is_syn_ack = false;
    bool parsed_l4 = false;
    int packet_family = AF_UNSPEC;
    struct in_addr src_ip4 = {0};
    struct in6_addr src_ip6;
    memset(&src_ip6, 0, sizeof(src_ip6));

    pthread_mutex_lock(&table_mutex);

    // 2. Parsování IP vrstvy (v4 nebo v6)
    if (ip_version == 4) {
        if (header->caplen < l2_hdr_len + sizeof(struct ip)) {
            pthread_mutex_unlock(&table_mutex);
            return;
        }

        proto = ip_hdr->ip_p;
        packet_family = AF_INET;
        src_ip4 = ip_hdr->ip_src;
        // Posun na transportní vrstvu
        int ip_hl = ip_hdr->ip_hl * 4;
        if (ip_hl < (int)sizeof(struct ip) || header->caplen < l2_hdr_len + (size_t)ip_hl) {
            pthread_mutex_unlock(&table_mutex);
            return;
        }
        
        if (proto == IPPROTO_TCP) {
            if (header->caplen < l2_hdr_len + (size_t)ip_hl + sizeof(struct tcphdr)) {
                pthread_mutex_unlock(&table_mutex);
                return;
            }

            struct tcphdr *tcp = (struct tcphdr *)(packet + l2_hdr_len + ip_hl);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            if (tcp->th_flags & TH_RST) is_rst = true;
            if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) is_syn_ack = true;
            parsed_l4 = true;
        } else if (proto == IPPROTO_UDP) {
            if (header->caplen < l2_hdr_len + (size_t)ip_hl + sizeof(struct udphdr)) {
                pthread_mutex_unlock(&table_mutex);
                return;
            }

            struct udphdr *udp = (struct udphdr *)(packet + l2_hdr_len + ip_hl);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            parsed_l4 = true;
        } else if (proto == IPPROTO_ICMP) {
            size_t icmp_off = l2_hdr_len + (size_t)ip_hl;
            if (header->caplen >= icmp_off + sizeof(struct icmp)) {
                handle_icmp_v4(packet + icmp_off, header->caplen - icmp_off, table);
            }
            // Logika pro ICMP (UDP unreachable) viz níže
            pthread_mutex_unlock(&table_mutex);
            return;
        }
    } else if (ip_version == 6) {
        if (header->caplen < l2_hdr_len + sizeof(struct ip6_hdr)) {
            pthread_mutex_unlock(&table_mutex);
            return;
        }

        struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + l2_hdr_len);
        proto = ip6->ip6_nxt;
        packet_family = AF_INET6;
        src_ip6 = ip6->ip6_src;
        size_t l4_off = l2_hdr_len + sizeof(struct ip6_hdr);

        // Zjednodušeně bez extension headers:
        if (proto == IPPROTO_TCP) {
            if (header->caplen < l4_off + sizeof(struct tcphdr)) {
                pthread_mutex_unlock(&table_mutex);
                return;
            }

            struct tcphdr *tcp = (struct tcphdr *)(packet + l4_off);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            if (tcp->th_flags & TH_RST) is_rst = true;
            if ((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) is_syn_ack = true;
            parsed_l4 = true;
        } else if (proto == IPPROTO_UDP) {
            if (header->caplen < l4_off + sizeof(struct udphdr)) {
                pthread_mutex_unlock(&table_mutex);
                return;
            }

            struct udphdr *udp = (struct udphdr *)(packet + l4_off);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            parsed_l4 = true;
        } else if (proto == IPPROTO_ICMPV6) {
            if (header->caplen >= l4_off + sizeof(struct icmp6_hdr)) {
                handle_icmp_v6(packet + l4_off, header->caplen - l4_off, table);
            }
            pthread_mutex_unlock(&table_mutex);
            return;
        }
    } else {
        pthread_mutex_unlock(&table_mutex);
        return;
    }

    if (!parsed_l4) {
        pthread_mutex_unlock(&table_mutex);
        return;
    }

    // 3. Vyhledání v tabulce a aktualizace stavu
    for (int i = 0; i < table->size; i++) {
        Packet_t *pckt = &table->packets[i];
        
        // Match: Zdrojová IP příchozího packetu == Cílová IP odeslaného packetu
        // A zároveň porty sedí (příchozí src_port == náš dst_port)
        if (!packet_matches_target(pckt, packet_family, &src_ip4, &src_ip6, src_port, dst_port)) {
            continue;
        }
            
            if (pckt->proto == SCAN_TCP && proto == IPPROTO_TCP) {
                if (is_rst) {
                    pckt->status = ST_CLOSED;
                } else if (is_syn_ack) {
                    pckt->status = ST_OPEN;
                }
            } else if (pckt->proto == SCAN_UDP && proto == IPPROTO_UDP) {
                // Pokud přišel UDP packet zpět (vzácné, ale možné), je OPEN
                pckt->status = ST_OPEN;
            }
    }
    pthread_mutex_unlock(&table_mutex);
}

void handle_icmp_v4(const u_char *icmp_ptr, size_t icmp_len, Table_packet_t *table) {
    if (icmp_len < sizeof(struct icmp) + sizeof(struct ip) + sizeof(struct udphdr)) {
        return;
    }

    struct icmp *icmp_hdr = (struct icmp *)icmp_ptr;
    
    // Typ 3, Kód 3 = Port Unreachable
    if (icmp_hdr->icmp_type == ICMP_UNREACH && icmp_hdr->icmp_code == ICMP_UNREACH_PORT) {
        // Uvnitř ICMP zprávy je kopie IP hlavičky a prvních 8 bajtů UDP hlavičky původního packetu
        struct ip *orig_ip = &icmp_hdr->icmp_ip;
        int orig_ip_hl = orig_ip->ip_hl * 4;
        if (orig_ip_hl < (int)sizeof(struct ip)) {
            return;
        }

        if (orig_ip->ip_p != IPPROTO_UDP) {
            return;
        }

        if (icmp_len < sizeof(struct icmp) + (size_t)orig_ip_hl + sizeof(struct udphdr)) {
            return;
        }

        struct udphdr *orig_udp = (struct udphdr *)((u_char *)orig_ip + orig_ip_hl);
        
        uint16_t orig_dst_port = ntohs(orig_udp->uh_dport);
        uint32_t orig_dst_ip = orig_ip->ip_dst.s_addr;

        for (int i = 0; i < table->size; i++) {
            if (table->packets[i].proto == SCAN_UDP &&
                table->packets[i].family == AF_INET &&
                table->packets[i].dst_port == orig_dst_port &&
                table->packets[i].dst_addr.addr.raddr4 == orig_dst_ip) {
                table->packets[i].status = ST_CLOSED;
            }
        }
    }
}

void handle_icmp_v6(const u_char *icmp_ptr, size_t icmp_len, Table_packet_t *table) {
    if (icmp_len < sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr) + sizeof(struct udphdr)) {
        return;
    }

    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)icmp_ptr;
    if (icmp6->icmp6_type != ICMP6_DST_UNREACH || icmp6->icmp6_code != ICMP6_DST_UNREACH_NOPORT) {
        return;
    }

    const struct ip6_hdr *orig_ip6 = (const struct ip6_hdr *)(icmp_ptr + sizeof(struct icmp6_hdr));
    if (orig_ip6->ip6_nxt != IPPROTO_UDP) {
        return;
    }

    const struct udphdr *orig_udp = (const struct udphdr *)((const u_char *)orig_ip6 + sizeof(struct ip6_hdr));
    uint16_t orig_dst_port = ntohs(orig_udp->uh_dport);

    for (int i = 0; i < table->size; i++) {
        if (table->packets[i].proto == SCAN_UDP &&
            table->packets[i].family == AF_INET6 &&
            table->packets[i].dst_port == orig_dst_port &&
            memcmp(&table->packets[i].dst_addr.addr.raddr6, &orig_ip6->ip6_dst, sizeof(struct in6_addr)) == 0) {
            table->packets[i].status = ST_CLOSED;
        }
    }
}