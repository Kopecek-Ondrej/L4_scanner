#include "scanner.h"
#include "error_code.h"
#include "address.h"
#include "protocol.h"
#include <netinet/in.h>
#include <netinet/ip.h>   // struct iphdr
// #include <netinet/tcp_portsh>  // struct tcphdr
#include <sys/socket.h>


#define IPV4 4
#define IPV6 6

int scan_destinations(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source){

    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source);

    int err = 0;
    Raw_sockets_t socks;
    Packet_t* packets = init_packets(scanner, destination);
    if(packets == NULL) RETURN_ERROR(ERR_SYS_MEM_ALLOC,"Failed to allocate memory");


    init_raw_sockets(&socks);

    //make two threads;
    //first activate the waiting one

    //then activate the sending one

    //send_packets()
    err = send_packets(scanner, destination, source, &socks, packets);


    //recieve_packets()


    return err;
}

int send_packets(Scanner_t *scanner, Destination_addresses_t *destination, Source_address_t *source, Raw_sockets_t *socks, Packet_t *packets){
    
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, scanner, destination, source, socks);
    int err = 0;
    for(size_t i = 0; i < destination->count; i++){

        if(scanner->tcp_use){
            err = send_with_tcp(&(destination->items[0]), scanner, source, socks->fd[TCP4_OUT], socks->fd[TCP6_OUT], packets);
            return err;
        }

        if(scanner->udp_use){
            err = send_with_udp(&(destination->items[0]), scanner, source, socks->fd[UDP4_OUT], socks->fd[UDP6_OUT], packets);
            return err;
        }

    }

    if(!(scanner->udp_use && scanner->tcp_use)){
        free_destination_addresses(destination);
        RETURN_ERROR(ERR_CLI_ARG,"No port has been selected");
    }

    return EXIT_OK;
}

int send_with_tcp(Resolved_address_t *items, Scanner_t *scanner,Source_address_t *source, int sock4, int sock6, Packet_t *packets){

    RETURN_IF_NULL(ERR_NO_ARGUMENTS, items, scanner, source);

    char send_buffer[4096];
    int packet_size = 0;
    uint16_t my_source_port = 12345;//todo::urcite musi zde byt nejaky volny port//musim napsat funkci, pro detekci meho portu
    uint16_t target_port;

    for(int i = 0; i < scanner->tcp_ports.port_cnt; i++){
    //todo:: vytvorit ...alokovat strukturu, co vse spoji
        target_port = get_port(&(scanner->tcp_ports), packets, items);
        // 2. Odešleme paket pomocí správného socketu
        if (items->family == AF_INET && sock4 != -1) {
            build_tcp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            // Pro IPv4 posíláme celý datagram (včetně námi vyrobené IP hlavičky)
            if (sendto(sock4, send_buffer, packet_size, 0, 
                    (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv4 selhalo");
            }
        } else if (items->family == AF_INET6 && sock6 != -1) {//todo:: fix -1 as magic num
            // Pro IPv6 posíláme jen TCP část (kernel si IP hlavičku dodá sám)
            build_tcp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            if (sendto(sock6, send_buffer, packet_size, 0, 
                    (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání IPv6 selhalo");
            }
        }

        packet_size = 0;
    }
    return EXIT_OK;
}

int send_with_udp(Resolved_address_t *items, Scanner_t *scanner,Source_address_t *source, int sock4, int sock6, Packet_t *packets){
    
    RETURN_IF_NULL(ERR_NO_ARGUMENTS, items, scanner, source);

    char send_buffer[4096];
    int packet_size = 0;
    uint16_t my_source_port = 12345;
    uint16_t target_port;

    for (int i = 0; i < scanner->udp_ports.port_cnt; i++) {
        target_port = get_port(&(scanner->udp_ports), packets, items);

        if (items->family == AF_INET && sock4 != -1) {
            build_udp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            
            if (sendto(sock4, send_buffer, packet_size, 0, 
                       (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání UDP IPv4 selhalo");
            }
        } 
        else if (items->family == AF_INET6 && sock6 != -1) {
            build_udp_packet(send_buffer, &packet_size, source, items, my_source_port, target_port);
            
            if (sendto(sock6, send_buffer, packet_size, 0, 
                       (struct sockaddr *)&(items->addr), items->addr_len) < 0) {
                perror("Odeslání UDP IPv6 selhalo");
            }
        }
        packet_size = 0;
    }
    return EXIT_OK;
}

//prisk::
//todo::test
int get_port(Ports_t *ports, Packet_t *packets, Resolved_address_t *items){

    RETURN_IF_NULL(ERR_NO_ARGUMENTS, ports);
    static int seq_number = 0;
    static int count_range = -1;
    static int position = 0;
    int port = -1;
    
    switch(ports->type){
        case SINGLE:
            port = ports->min;
        break;

        case RANGE:
            count_range++;    //in first iteration it will be count = 0
            port = ports->min + count_range;
        break;
            
        case MULTIP:
            position = read_next_port(ports->ports_array, position, &port);
        break;
    }

    packets[0].seq_number = seq_number;
    seq_number++;
    packets[0].tries = 1;
    packets[0].status = ST_PENDING;
    packets[0].port = port;
    packets[0].proto = items->family;
    packets[0].target_addr = items->addr;


    DEBUG_PRINT("get_port:: port: %d", port);

    return port;

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

