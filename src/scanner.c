#include "scanner.h"
#include "error_code.h"
#include "address.h"

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

int scan_with_tcp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source){
    for(int i = 0; i < scanner->TCP.port_cnt; i++){
        //podle toho jaka je destinace rodina tak to poslu ze source IP adresy
        
    }

}

int scan_with_udp(Resolved_address_t *times, Scanner_t *scanner,Source_address_t *source){
    for(int i = 0; i < scanner->UDP.port_cnt; i++){
        
    }
}