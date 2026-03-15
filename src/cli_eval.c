#include "error_code.h"
#include "cli_eval.h"
#include "cli_parser.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define DECIMAL_BASE 10
#define PARSE_END 33

int eval_arguments(Arguments_t *args, Scanner_t *scanner){
    if (args == NULL || scanner == NULL) {
        return ERR_CLI_ARG;
    }
    //default value
    scanner->timeout = 1000;

    if(args->help){
        scanner->mode = MODE_SHOW_HELP;
        return EXIT_OK;
    }

    if(args->show_interface){
        //call getifaddrs()
        if(args->arg_cnt == 2){
            scanner->mode = MODE_SHOW_INTERFACE;
            return EXIT_OK;
        }
    }

    if(args->interface == NULL){
        RETURN_ERROR(ERR_CLI_ARG, "INTERFACE is mandatory parameter");
    }
    scanner->interface = args->interface;

    if(args->hostname == NULL){
        RETURN_ERROR(ERR_CLI_ARG, "HOST is mandatory parameter");
    }else{
        scanner->hostname = args->hostname; //is this valid? i think it is because it points to the main() parametr
    }

    if(args->timeout != NULL){
        char* end;
        scanner->timeout = strtol(args->timeout, &end, DECIMAL_BASE);
    }

    if((args->u_ports == NULL) && (args->t_ports == NULL)){
        RETURN_ERROR(ERR_CLI_ARG, "PORTs must be specified");
    }else{
        int err;
        
        err = eval_ports(args->t_ports, &scanner->TCP);
        if(err != EXIT_OK){
            return err;
        }
        err = eval_ports(args->u_ports, &scanner->UDP);
        if(err != EXIT_OK){
            return err;
        }
    }

    scanner->mode = MODE_SCAN;
    return EXIT_OK;

}

int eval_ports(char* s_ports, Ports_t *ports){
    //no s_ports have been assigned
    //there is init value NULL
    if(s_ports == NULL){
        return EXIT_OK;
    }
    //help:: jsou tri moznosti, jak to muze vypadat
    //-t 22, -u 1-65535, -t 22,23,24.
    //currently I assume only correct ways of entering data

    if(strchr(s_ports, '-') != NULL){
        char *dash = strchr(s_ports, '-');
        long first = strtol(s_ports, NULL, DECIMAL_BASE);
        long second = strtol(dash + 1, NULL, DECIMAL_BASE);

        if (first < 1 || first > 65535 || second < 1 || second > 65535) {
            RETURN_ERROR(ERR_CLI_ARG, "Invalid range");
        }

        ports->min = (first < second) ? (int)first : (int)second;
        ports->max = (first > second) ? (int)first : (int)second;
        ports->port_cnt = ports->max - ports->min + 1;
        ports->ports_array = NULL;
        ports->type = RANGE;
    }else if(strchr(s_ports, ',') != NULL){
        // reject trailing comma "22,"
        size_t len = strlen(s_ports);
        if (len == 0 || s_ports[len - 1] == ',') {
            RETURN_ERROR(ERR_CLI_ARG, "Invalid port list: trailing comma");
        }
        
        int err = count_ports(s_ports);
        if(err < 0){
            RETURN_ERROR(ERR_CLI_ARG, "Invalid port list");
        }
        ports->port_cnt = err;
        ports->ports_array = s_ports;
        ports->type = MULTIP;
    }else{
        char *end;
        long val = strtol(s_ports, &end, DECIMAL_BASE);
        //prisk:: unsufcient evaluation
        //"22abc" --> 22
        if(val == 0){
            RETURN_ERROR(ERR_CLI_ARG, "Invalid port input");
        }
        //same values mean only one port
        if(val < 1 || val > 65535){
            RETURN_ERROR(ERR_PORT_RANGE, "Invalid range");
        }
        ports->port_cnt = 1;
        ports->min = val;
        ports->max = val;
        ports->type = SINGLE;
    }
    return 0;
}

void print_help(){
    fprintf(stdout, "FOLLOW THIS FORMAT: \n");
    fprintf(stdout, "./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT] [-h | --help]\n");
}

int parse_number(const char **str, int *value){
    if (!isdigit(**str))
        return ERR_CLI_ARG;

    long num = 0;

    while (isdigit(**str)) {
        num = num * 10 + (**str - '0');

        if (num > PORT_MAX)
            return ERR_PORT_RANGE;

        (*str)++;
    }

    *value = (int)num;
    return EXIT_OK;
}

int check_delimiter(const char **str){
    if (**str == '\0')
        return PARSE_END;

    if (**str != ',')
        return ERR_CLI_ARG;

    (*str)++;

    if (**str == '\0')
        return ERR_CLI_ARG;

    return EXIT_OK;
}

int next_port(const char **str, int *port){
    int rc;

    rc = parse_number(str, port);
    if (rc != EXIT_OK)
        return ERR_CLI_ARG;

    rc = check_delimiter(str);

    if (rc == PARSE_END)
        return EXIT_OK;

    if (rc == ERR_CLI_ARG)
        return ERR_CLI_ARG;

    return EXIT_OK;
}

int count_ports(const char *s){
    int port;
    int count = 0;

    while (*s) {
        int rc = next_port(&s, &port);

        if (rc == ERR_CLI_ARG)
            return ERR_CLI_ARG;

        count++;
    }

    return count;
}