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

typedef enum {
    TCP4_OUT, TCP6_OUT,
    TCP4_IN,  TCP6_IN,
    UDP4_OUT, UDP6_OUT,
    UDP4_ICMP_IN, UDP6_ICMP_IN,
    SOCKET_COUNT // Automaticky spočítá počet prvků (zde 8)
} socket_type_t;

typedef struct {
    int fd[SOCKET_COUNT];
} Raw_sockets_t;

typedef enum { SCAN_TCP, SCAN_UDP } proto_t;
typedef enum { ST_PENDING, ST_OPEN, ST_CLOSED, ST_FILTERED } state_t;

typedef struct {
    // UNIKÁTNÍ IDENTIFIKÁTORY (Klíč)
    struct sockaddr_storage target_addr; // Cílová IP
    uint16_t port;                       // Cílový port
    proto_t proto;                       // TCP nebo UDP
    
    // STAVOVÉ INFORMACE
    state_t status;
    int tries;                           // Počet pokusů (1 nebo 2)
    struct timespec last_sent;           // Čas posledního odeslání
    
    uint32_t seq_number;                 // Sekvenční číslo, které jsme poslali (pro TCP)
} Packet_t;

unsigned short checksum(unsigned short *ptr, int nbytes);

int build_udp_packet(char *packet, int *packet_len, 
                     Source_address_t *source, 
                     Resolved_address_t *dest, 
                     uint16_t src_port, uint16_t dst_port);

int build_tcp_packet(char *packet, int *packet_len, 
                     Source_address_t *source, 
                     Resolved_address_t *dest, 
                     uint16_t src_port, uint16_t dst_port);

int init_raw_sockets(Raw_sockets_t *socks);
void close_raw_sockets(Raw_sockets_t *socks);

Packet_t* init_packets(Scanner_t *scanner,Destination_addresses_t *destination);
#endif// __PROTOKOL_H