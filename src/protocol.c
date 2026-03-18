
#include "protocol.h"
#include "address.h"
#include "error_code.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

// Funkce pro výpočet kontrolního součtu
unsigned short checksum(unsigned short *ptr, int nbytes){
    long sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes == 1) sum += *(unsigned char*)ptr;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int build_udp_packet(char *packet, int *packet_len, 
                     Source_address_t *source, 
                     Resolved_address_t *dest, 
                     uint16_t src_port, uint16_t dst_port) {

    memset(packet, 0, 4096);

    if (dest->family == AF_INET) {
        struct iphdr *iph = (struct iphdr *) packet;
        struct udphdr *udph = (struct udphdr *) (packet + sizeof(struct iphdr));
        
        struct sockaddr_in *s4 = (struct sockaddr_in *)&(source->addr_ipv4);
        struct sockaddr_in *d4 = (struct sockaddr_in *)&dest->addr;

        // IP hlavička
        iph->ihl = 5;
        iph->version = 4;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
        iph->id = htons(54321);
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = s4->sin_addr.s_addr;
        iph->daddr = d4->sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

        // UDP hlavička
        udph->source = htons(src_port);
        udph->dest = htons(dst_port);
        udph->len = htons(sizeof(struct udphdr)); // Délka UDP hlavičky + dat (data jsou 0)
        udph->check = 0; // U UDP IPv4 může být checksum 0 (nepovinný), ale je lepší ho mít

        // Pseudo-hlavička pro UDP checksum (stejná logika jako u TCP)
        struct pseudo_ipv4 p4;
        p4.src = iph->saddr;
        p4.dst = iph->daddr;
        p4.zero = 0;
        p4.proto = IPPROTO_UDP;
        p4.len = udph->len;

        char b[sizeof(struct pseudo_ipv4) + sizeof(struct udphdr)];
        memcpy(b, &p4, sizeof(struct pseudo_ipv4));
        memcpy(b + sizeof(struct pseudo_ipv4), udph, sizeof(struct udphdr));
        udph->check = checksum((unsigned short *)b, sizeof(b));

        *packet_len = ntohs(iph->tot_len);
        return 0;

    } else if (dest->family == AF_INET6) {
        struct udphdr *udph = (struct udphdr *) packet;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&(source->addr_ipv6);
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dest->addr;

        udph->source = htons(src_port);
        udph->dest = htons(dst_port);
        udph->len = htons(sizeof(struct udphdr));

        // UDP Checksum pro IPv6 (tady je POVINNÝ)
        struct pseudo_ipv6 p6;
        memcpy(&p6.src, &s6->sin6_addr, 16);
        memcpy(&p6.dst, &d6->sin6_addr, 16);
        p6.len = htonl(sizeof(struct udphdr));
        memset(p6.zero, 0, 3);
        p6.next_header = IPPROTO_UDP;

        char b[sizeof(struct pseudo_ipv6) + sizeof(struct udphdr)];
        memcpy(b, &p6, sizeof(struct pseudo_ipv6));
        memcpy(b + sizeof(struct pseudo_ipv6), udph, sizeof(struct udphdr));
        udph->check = checksum((unsigned short *)b, sizeof(b));

        *packet_len = sizeof(struct udphdr);
        return 0;
    }
    return -1;
}

int build_tcp_packet(char *packet, int *packet_len, 
                     Source_address_t *source, 
                     Resolved_address_t *dest, 
                     uint16_t src_port, uint16_t dst_port) {

    struct tcphdr *tcph;

    /* build on a clean buffer so unused header fields start at zero */
    memset(packet, 0, 4096);

    if (dest->family == AF_INET) {
        // --- IPv4 VARIANT ---
        struct iphdr *iph = (struct iphdr *) packet;
        tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));
        
        struct sockaddr_in *s4 = (struct sockaddr_in *)&(source->addr_ipv4);
        struct sockaddr_in *d4 = (struct sockaddr_in *)&dest->addr;

        // Sestavení IP hlavičky
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = s4->sin_addr.s_addr;
        iph->daddr = d4->sin_addr.s_addr;

        iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));//
        // iph->check = 0; // Kernel dopočítá, pokud není nastaveno IP_HDRINCL
        //prisk:: here 

        // Sestavení TCP hlavičky
        memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source = htons(src_port);
        tcph->dest = htons(dst_port);
        tcph->syn = 1; //super important
        tcph->doff = 5;
        tcph->window = htons(65535);

        // Checksum pro IPv4
        struct pseudo_ipv4 p4;
        p4.src = iph->saddr;
        p4.dst = iph->daddr;
        p4.zero = 0;
        p4.proto = IPPROTO_TCP;
        p4.len = htons(sizeof(struct tcphdr));

        // Musíme spočítat checksum z pseudo-hlavičky + tcp hlavičky
        char b[sizeof(struct pseudo_ipv4) + sizeof(struct tcphdr)];
        memcpy(b, &p4, sizeof(struct pseudo_ipv4));
        memcpy(b + sizeof(struct pseudo_ipv4), tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)b, sizeof(b));

        *packet_len = ntohs(iph->tot_len);
        return 0;

    } else if (dest->family == AF_INET6) {
        // --- IPv6 VARIANT ---
        // U IPv6 raw socketů (IPPROTO_TCP) kernel obvykle IP hlavičku doplňuje sám.
        // Budeme tedy stavět pouze TCP hlavičku.
        tcph = (struct tcphdr *) packet;
        
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&(source->addr_ipv6);
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)&dest->addr;

        memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source = htons(src_port);
        tcph->dest = htons(dst_port);
        tcph->syn = 1;
        tcph->doff = 5;
        tcph->window = htons(65535);

        // Checksum pro IPv6 (naprosto kritické, bez něj to OS nepustí)
        struct pseudo_ipv6 p6;
        memcpy(&p6.src, &s6->sin6_addr, 16);
        memcpy(&p6.dst, &d6->sin6_addr, 16);
        p6.len = htonl(sizeof(struct tcphdr));
        memset(p6.zero, 0, 3);
        p6.next_header = IPPROTO_TCP;

        char b[sizeof(struct pseudo_ipv6) + sizeof(struct tcphdr)];
        memcpy(b, &p6, sizeof(struct pseudo_ipv6));
        memcpy(b + sizeof(struct pseudo_ipv6), tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short *)b, sizeof(b));

        *packet_len = sizeof(struct tcphdr);
        return 0;
    }

    return -1;
}

int init_raw_sockets(Raw_sockets_t *socks) {
    int one = 1;

    // 1. Inicializace všech prvků pole na -1
    for (int i = 0; i < SOCKET_COUNT; i++) {
        socks->fd[i] = -1;
    }

    // 2. Vytvoření socketů
    socks->fd[TCP4_OUT]     = socket(AF_INET,  SOCK_RAW, IPPROTO_TCP);
    socks->fd[TCP6_OUT]     = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    socks->fd[TCP4_IN]      = socket(AF_INET,  SOCK_RAW, IPPROTO_TCP);
    socks->fd[TCP6_IN]      = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    socks->fd[UDP4_OUT]     = socket(AF_INET,  SOCK_RAW, IPPROTO_UDP);
    socks->fd[UDP6_OUT]     = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    socks->fd[UDP4_ICMP_IN] = socket(AF_INET,  SOCK_RAW, IPPROTO_ICMP);
    socks->fd[UDP6_ICMP_IN] = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    // 3. Kontrola odesílacích socketů (kritické pro běh)
    if (socks->fd[TCP4_OUT] < 0 && socks->fd[TCP6_OUT] < 0) {
        fprintf(stderr, "Chyba: Nepodařilo se otevřít TCP odesílací sockety (IPv4 ani IPv6)\n");
        return -1;
    }

    // 4. Nastavení IP_HDRINCL pro IPv4 odesílací sockety
    if (socks->fd[TCP4_OUT] >= 0) {
        if (setsockopt(socks->fd[TCP4_OUT], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("Setsockopt TCP4_OUT IP_HDRINCL failed");
        }
    }

    if (socks->fd[UDP4_OUT] >= 0) {
        if (setsockopt(socks->fd[UDP4_OUT], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("Setsockopt UDP4_OUT IP_HDRINCL failed");
        }
    }

    // 5. Kontrola přijímacích socketů (volitelně, stačí varování)
    for (int i = 0; i < SOCKET_COUNT; i++) {
        if (socks->fd[i] < 0) {
            RETURN_ERROR(-1, "error opening socket: %d\n", i);
        }
    }

    return 0;
}

void close_raw_sockets(Raw_sockets_t *socks) {

    for (int i = 0; i < SOCKET_COUNT; i++) {
        if (socks->fd[i] != -1) {
            close(socks->fd[i]);
            socks->fd[i] = -1 ;
        }
    }
}

Packet_t* init_packets(Scanner_t *scanner,Destination_addresses_t *destination, int *table_size){
    int packets_to_allocate = 0;
    Packet_t *packets;
    
    if(scanner->tcp_use){
        packets_to_allocate += scanner->tcp_ports.port_cnt;
    }

    if(scanner->udp_use){
        packets_to_allocate += scanner->udp_ports.port_cnt;
    }

    packets_to_allocate *= destination->count;

    packets = calloc(packets_to_allocate, sizeof(Packet_t)); //prisk:: malloc

    if(packets == NULL){
        return NULL;
    }

    *table_size = packets_to_allocate;
    return packets;
}

void free_packets(Packet_t *packets){
    if(packets != NULL){
        free(packets);
    }
}