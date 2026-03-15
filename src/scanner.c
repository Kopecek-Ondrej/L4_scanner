#include "scanner.h"
#include "error_code.h"
#include "address.h"
#include "protocol.h"
#include <netinet/ip.h>   // struct iphdr
#include <netinet/tcp.h>  // struct tcphdr


#define IPV4 4
#define IPV6 6

int scan_destinations(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source){
    
    if((scanner == NULL) || (destination == NULL)){
        RETURN_ERROR(ERR_NO_ARGUMENTS, "arguments is NULL");
    }

    for(int i = 0; i < destination->count; i++){

        if(scanner->tcp_use) scan_with_tcp(&(destination->items[0]), scanner, source);

        if(scanner->udp_use) scan_with_udp(&(destination->items[0]), scanner, source);


    }

    if(!(scanner->udp_use && scanner->tcp_use)){
        free_destination_addresses(destination);
        RETURN_ERROR(ERR_CLI_ARG,"No port has been selected");
    }
}

int scan_with_tcp(Resolved_address_t *items, Scanner_t *scanner,Source_address_t *source){

    char send_buffer[4096];
    int packet_size = 0;
    uint16_t my_source_port = 12345;
    uint16_t target_port;

    for(int i = 0; i < scanner->TCP.port_cnt; i++){
    
        target_port = get_port(&(scanner->TCP));
        // 2. Odešleme paket pomocí správného socketu
        if (items->family == AF_INET) {
            build_syn_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            // Pro IPv4 posíláme celý datagram (včetně námi vyrobené IP hlavičky)
            if (sendto(sock4, send_buffer, packet_size, 0, 
                    (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv4 selhalo");
            }
        } else if (items->family == AF_INET6) {
            // Pro IPv6 posíláme jen TCP část (kernel si IP hlavičku dodá sám)
            build_syn_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            if (sendto(sock6, send_buffer, packet_size, 0, 
                    (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv6 selhalo");
            }
        }

        packet_size = 0;
    }

}

int scan_with_udp(Resolved_address_t *items, Scanner_t *scanner,Source_address_t *source){
    for(int i = 0; i < scanner->UDP.port_cnt; i++){
        
    }
}

int get_port(Ports_t *ports){
    static int count_range = -1;
    static int position = 0;
    int port;
    
    switch(ports->type){
        case SINGLE:
            return ports->min;
        break;

        case RANGE:
            count_range++;    //in first iteration it will be count = 0
            return ports->min + count_range;
        break;
            position = read_next_port(ports->ports_array, position, &port);
        case MULTIP:

        break;
    }
}


int read_next_port(char *s, int pos, int *port){
    int value = 0;

    while (s[pos] != '\0' && s[pos] != ',') {
        value = value * 10 + (s[pos] - '0');
        pos++;
    }

    *port = value;

    printf("%d\n", value);

    if (s[pos] == ',')
        pos++;  // skip comma

    return pos;
}