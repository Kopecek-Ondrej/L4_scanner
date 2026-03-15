#ifndef __PROTOKOL_H
#define __PROTOKOL_H

#include <stdint.h>
#include "address.h"

// Pseudo-hlavička pro IPv4
struct pseudo_ipv4 {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
};

// Pseudo-hlavička pro IPv6
struct pseudo_ipv6 {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t len;
    uint8_t zero[3];
    uint8_t next_header;
};

unsigned short checksum(unsigned short *ptr, int nbytes);

int build_syn_packet(char *packet, int *packet_len, 
                     Source_address_t *source, 
                     Resolved_address_t *dest, 
                     uint16_t src_port, uint16_t dst_port);
#endif// __PROTOKOL_H