#ifndef TEST_CLI_H
#define TEST_CLI_H

#include "helper.h"

int test_help_sets_mode(void);
int test_missing_host_fails(void);
int test_trailing_comma_is_error(void);
int test_cli_eval_1(void);
int test_parse_number_valid(void);
int test_parse_number_invalid_char(void);
int test_parse_number_overflow(void);
int test_check_delimiter_end(void);
int test_check_delimiter_missing_next(void);
int test_count_ports_valid(void);
int test_parse_number_invalid(void);
int test_eval_ports_range(void);
int test_eval_ports_single_invalid(void);
int test_parse_arguments_invalid_option(void);
int test_parse_arguments_too_many_positionals(void);
int test_parse_arguments_show_interface_only(void);
int test_eval_arguments_missing_interface(void);
int test_eval_arguments_missing_ports(void);
int test_eval_arguments_help_mode(void);
int test_eval_arguments_show_interface_mode(void);
#endif
