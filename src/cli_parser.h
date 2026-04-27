/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#ifndef __cli_parser_H__
#define __cli_parser_H__
#include <pcap.h>
#include <stdbool.h>
#include <sys/types.h>

#define PORT_MAX 65535
#define DECIMAL_BASE 10
#define PARSE_END 33
#define DEFAULT_TIMEOUT 1000

/**
 * @brief Raw CLI argument strings captured before evaluation.
 */
typedef struct {
    char* interface;
    char* u_ports;
    char* t_ports;
    char* hostname;
    char* timeout;
    int arg_cnt;
    bool help;
    bool show_interface;
} Arguments_t;

typedef enum {
    SINGLE,
    RANGE,
    MULTIP,
} Ports_def_type_t;

/**
 * @brief Parsed port specification (single, range, or multiple).
 */
typedef struct {
    char* ports_array;
    int port_cnt;
    int min;
    int max;

    Ports_def_type_t type;
} Ports_t;

typedef enum {
    MODE_SHOW_INTERFACE,
    MODE_SHOW_HELP,
    MODE_SCAN,
} Scanner_mode_t;

/**
 * @brief Evaluated CLI settings ready for scanning.
 */
typedef struct {
    Ports_t tcp_ports;
    Ports_t udp_ports;
    bool tcp_use;
    bool udp_use;

    char* interface;
    char* hostname;
    int timeout;

    pcap_t* pcap_handle;

    Scanner_mode_t mode;
} Cli_Parser_t;

/**
 * @brief Check if string contains any alphabetic character.
 */
int contains_letter(char* str);

/**
 * @brief Parse raw argv into argument structure.
 */
int parse_arguments(int argc, char* argv[], Arguments_t* args);

/**
 * @brief Print collected raw arguments for debugging.
 */
void print_arguments(const Arguments_t* args);

/**
 * @brief Evaluate arguments into parser settings and mode.
 */
int eval_arguments(Arguments_t* args, Cli_Parser_t* parser);

/**
 * @brief Parse port definition string into Ports_t.
 */
int eval_ports(char* s_ports, Ports_t* ports);

/**
 * @brief Print help message.
 */
void print_help();

/**
 * @brief Parse decimal number from string pointer.
 */
int parse_number(const char** str, int* value);

/**
 * @brief Validate expected delimiter in port list.
 */
int check_delimiter(const char** str);

/**
 * @brief Read next port value from a list string.
 */
int next_port(const char** str, int* port);

/**
 * @brief Count total ports described by a port string.
 */
int count_ports(const char* s, int* port_cnt);
#endif //__cli_parser_H__