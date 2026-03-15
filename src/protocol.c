
#include "protokol.h"
#include "address.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

// Předpokládáme existenci funkce checksum() z předchozích zpráv

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

int build_syn_packet(char *packet, int *packet_len, 
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
        iph->check = 0; // Kernel dopočítá, pokud není nastaveno IP_HDRINCL

        // Sestavení TCP hlavičky
        memset(tcph, 0, sizeof(struct tcphdr));
        tcph->source = htons(src_port);
        tcph->dest = htons(dst_port);
        tcph->syn = 1;
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