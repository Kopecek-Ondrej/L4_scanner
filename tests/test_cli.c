#include "test_cli.h"

#include "cli_eval.h"
#include "error_code.h"
#include "helper.h"

#include <stdio.h>
#include <string.h>

int test_help_sets_mode(void) {
    char* argv[] = {"prog", "--help"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args    = {0};
    Parser_t   parser = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments help");
    ASSERT_EQ_INT(1, args.help, "args.help set");

    rc = eval_arguments(&args, &parser);
    ASSERT_EQ_INT(EXIT_OK, rc, "eval_arguments help");
    ASSERT_EQ_INT(MODE_SHOW_HELP, parser.mode, "parser.mode help");
    return 0;
}

int test_missing_host_fails(void) {
    char* argv[] = {"prog", "-t", "22"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args    = {0};
    Parser_t   parser = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments missing host");

    rc = eval_arguments(&args, &parser);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments missing host error");
    return 0;
}

int test_trailing_comma_is_error(void) {
    char* argv[] = {"prog", "-u", "22,", "host"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args    = {0};
    Parser_t   parser = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments trailing comma");

    rc = eval_arguments(&args, &parser);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments trailing comma error");
    return EXIT_OK;
}

int test_cli_eval_1(void) {
    Arguments_t args    = {0};
    Parser_t   scan    = {0};
    args.interface      = "eth0";
    args.u_ports        = "58,99,5,6,4,98,99,876,9";
    args.t_ports        = "88,9,123,2345,6000";
    args.hostname       = "www.seznam.cz";
    args.arg_cnt        = 5; // just not less than 3
    args.show_interface = false;

    int rc = eval_arguments(&args, &scan);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments trailing comma");
    ASSERT_EQ_INT(MODE_SCAN, scan.mode, "WRONG mode");
    ASSERT_EQ_INT(DEFAULT_TIMEOUT, scan.timeout, "WRONG default timeout");
    ASSERT_EQ_STR(args.hostname, scan.hostname, "WRONG hostname");
    ASSERT_EQ_STR("eth0", scan.interface, "WRONG interface");
    ASSERT_EQ_INT(1, scan.tcp_use, "TCP ports are set to be unused");
    ASSERT_EQ_INT(1, scan.udp_use, "UDP ports are set to be unused");
    ASSERT_EQ_INT(MULTIP, scan.tcp_ports.type, "TCP ports are supposed to be MULTIP");
    ASSERT_EQ_INT(MULTIP, scan.udp_ports.type, "UDP ports are supposed to be MULTIP");
    ASSERT_EQ_INT(9, scan.udp_ports.port_cnt, "WRONG port count");
    ASSERT_EQ_INT(5, scan.tcp_ports.port_cnt, "WRONG port count");
    return EXIT_OK;
}

// todo:: more relevant tests

int test_parse_number_invalid(void) {
    const char* s     = "123abc";
    int         value = 0;

    int rc = parse_number(&s, &value);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "parsing alpha-numeric strings wrong");
    return EXIT_OK;
}

int test_parse_number_valid(void) {
    const char* s     = "6008";
    int         value = 0;

    int rc = parse_number(&s, &value);
    ASSERT_EQ_INT(EXIT_OK, rc, "returned error");
    ASSERT_EQ_INT(6008, value, "parsed the number wrong");
    return EXIT_OK;
}

int test_parse_number_invalid_char(void) {
    const char* s     = "x99";
    int         value = 0;

    int rc = parse_number(&s, &value);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "parse_number invalid char rc");
    return EXIT_OK;
}

int test_parse_number_overflow(void) {
    const char* s     = "70000";
    int         value = 0;

    int rc = parse_number(&s, &value);
    ASSERT_EQ_INT(ERR_PORT_RANGE, rc, "parse_number overflow rc");
    return EXIT_OK;
}

int test_check_delimiter_end(void) {
    const char* s = "";

    int rc = check_delimiter(&s);
    ASSERT_EQ_INT(PARSE_END, rc, "check_delimiter end rc");
    return EXIT_OK;
}

int test_check_delimiter_missing_next(void) {
    const char* s = ",";

    int rc = check_delimiter(&s);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "check_delimiter missing next rc");
    return EXIT_OK;
}

int test_count_ports_valid(void) {
    const char* s        = "1,2,3";
    int         port_cnt = 0;

    int rc = count_ports(s, &port_cnt);
    ASSERT_EQ_INT(EXIT_OK, rc, "returned error");
    ASSERT_EQ_INT(3, port_cnt, "count_ports valid rc");
    return EXIT_OK;
}

int test_eval_ports_range(void) {
    Ports_t ports   = {0};
    char    input[] = "10-20";

    int rc = eval_ports(input, &ports);
    ASSERT_EQ_INT(EXIT_OK, rc, "eval_ports range rc");
    ASSERT_EQ_INT(RANGE, ports.type, "eval_ports range type");
    ASSERT_EQ_INT(10, ports.min, "eval_ports range min");
    ASSERT_EQ_INT(20, ports.max, "eval_ports range max");
    ASSERT_EQ_INT(11, ports.port_cnt, "eval_ports range count");
    return EXIT_OK;
}

int test_eval_ports_single_invalid(void) {
    Ports_t ports   = {0};
    char    input[] = "0";

    int rc = eval_ports(input, &ports);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_ports single invalid rc");
    return EXIT_OK;
}

int test_parse_arguments_invalid_option(void) {
    char* argv[] = {"prog", "-z"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "parse_arguments invalid option");
    return EXIT_OK;
}

int test_parse_arguments_too_many_positionals(void) {
    char* argv[] = {"prog", "-i", "eth0", "host", "extra"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "parse_arguments too many positionals");
    return EXIT_OK;
}

int test_parse_arguments_show_interface_only(void) {
    char* argv[] = {"prog", "-i"};
    int   argc   = (int)(sizeof(argv) / sizeof(argv[0]));

    Arguments_t args = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments show interface rc");
    ASSERT_EQ_INT(1, args.show_interface, "show_interface flag not set");
    ASSERT_EQ_INT(2, args.arg_cnt, "arg_cnt for interface only");
    return EXIT_OK;
}

int test_eval_arguments_missing_interface(void) {
    Arguments_t args = {0};
    Parser_t   scan = {0};
    args.hostname    = "host";
    args.t_ports     = "22";

    int rc = eval_arguments(&args, &scan);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments missing interface");
    return EXIT_OK;
}

int test_eval_arguments_missing_ports(void) {
    Arguments_t args = {0};
    Parser_t   scan = {0};
    args.interface   = "eth0";
    args.hostname    = "host";

    int rc = eval_arguments(&args, &scan);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments missing ports");
    return EXIT_OK;
}

int test_eval_arguments_help_mode(void) {
    Arguments_t args = {0};
    Parser_t   scan = {0};
    args.help        = true;

    int rc = eval_arguments(&args, &scan);
    ASSERT_EQ_INT(EXIT_OK, rc, "eval_arguments help rc");
    ASSERT_EQ_INT(MODE_SHOW_HELP, scan.mode, "eval_arguments help mode");
    return EXIT_OK;
}

int test_eval_arguments_show_interface_mode(void) {
    Arguments_t args    = {0};
    Parser_t   scan    = {0};
    args.show_interface = true;
    args.arg_cnt        = 2;

    int rc = eval_arguments(&args, &scan);
    ASSERT_EQ_INT(EXIT_OK, rc, "eval_arguments show interface rc");
    ASSERT_EQ_INT(MODE_SHOW_INTERFACE, scan.mode, "eval_arguments show interface mode");
    return EXIT_OK;
}
