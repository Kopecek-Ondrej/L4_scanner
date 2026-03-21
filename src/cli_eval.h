#ifndef __CLI_EVAL_H__
#define __CLI_EVAL_H__
#include <stdbool.h>
#include <pcap.h>

#define PORT_MAX 65535
#define DECIMAL_BASE 10
#define PARSE_END 33
#define DEFAULT_TIMEOUT 1000

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

	pcap_t *pcap_handle;

	Scanner_mode_t mode;
}Parser_t;

int parse_arguments(int argc, char* argv[], Arguments_t *args);

void print_arguments(const Arguments_t *args);

int eval_arguments(Arguments_t *args, Parser_t *parser);

int eval_ports(char* s_ports, Ports_t *ports);

void print_help();

int parse_number(const char **str, int *value);

int check_delimiter(const char **str);

int next_port(const char **str, int *port);

int count_ports(const char *s, int *port_cnt);
#endif //__CLI_EVAL_H__