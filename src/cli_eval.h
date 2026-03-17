#ifndef __CLI_EVAL_H__
#define __CLI_EVAL_H__
#include "cli_parser.h"

#define PORT_MAX 65535

typedef enum{
	SINGLE,
	RANGE,
	MULTIP,
}Ports_def_type_t;

typedef struct{
	// TypeProtokol_t type;
	char *ports_array;
	int port_cnt;
	int min;
	int max;

	Ports_def_type_t type;
}Ports_t;

// typedef *Protokol_t pProtokol_t;
typedef enum{
	MODE_SHOW_INTERFACE,
	MODE_SHOW_HELP,
	MODE_SCAN,
}Scanner_mode_t;

typedef struct{
	Ports_t tcp_ports;
	Ports_t udp_ports;
	bool tcp_use;
	bool udp_use;

	char *interface;
	char *hostname;
	int timeout;

	Scanner_mode_t mode;
}Scanner_t;

int eval_arguments(Arguments_t *args, Scanner_t *scanner);

int eval_ports(char* s_ports, Ports_t *ports);

void print_help();

int parse_number(const char **str, int *value);

int check_delimiter(const char **str);

int next_port(const char **str, int *port);

int count_ports(const char *s);
#endif //__CLI_EVAL_H__