#ifndef __CLI_PARSER__
#define __CLI_PARSER__

#include <stdbool.h>

typedef struct {
    char* interface; //
    char* u_ports; //
    char* t_ports; //
    char* hostname; //
    char* timeout; //
    int arg_cnt;
    bool help;  //
    bool show_interface;    //
}Arguments_t;

int parse_arguments(int argc, char* argv[], Arguments_t *args);

void print_arguments(const Arguments_t *args);

#endif // __CLI_PARSER__