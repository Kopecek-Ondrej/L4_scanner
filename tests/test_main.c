#include "helper.h"
#include "test_address.h"
#include "test_cli.h"
#include "test_interface.h"
#include "test_scanner.h"
#include <stdio.h>

int main(void) {
    int tests_passed = 0;
    int tests_failed = 0;
    int total = 0;

    run_test(test_help_sets_mode, "test_help_sets_mode", &tests_passed, &tests_failed, &total);
    run_test(test_missing_host_fails, "test_missing_host_fails", &tests_passed, &tests_failed, &total);
    run_test(test_trailing_comma_is_error, "test_trailing_comma_is_error", &tests_passed, &tests_failed, &total);
    run_test(test_cli_eval_1, "test_cli_eval_1", &tests_passed, &tests_failed, &total);
    run_test(test_parse_number_valid, "test_parse_number_valid", &tests_passed, &tests_failed, &total);
    run_test(test_parse_number_invalid, "test_parse_number_invalid", &tests_passed, &tests_failed, &total);
    run_test(test_parse_number_invalid_char, "test_parse_number_invalid_char", &tests_passed, &tests_failed, &total);
    run_test(test_parse_number_overflow, "test_parse_number_overflow", &tests_passed, &tests_failed, &total);
    run_test(test_check_delimiter_end, "test_check_delimiter_end", &tests_passed, &tests_failed, &total);
    run_test(test_check_delimiter_missing_next, "test_check_delimiter_missing_next", &tests_passed, &tests_failed, &total);
    run_test(test_count_ports_valid, "test_count_ports_valid", &tests_passed, &tests_failed, &total);
    run_test(test_eval_ports_range, "test_eval_ports_range", &tests_passed, &tests_failed, &total);
    run_test(test_eval_ports_single_invalid, "test_eval_ports_single_invalid", &tests_passed, &tests_failed, &total);
    run_test(test_parse_arguments_invalid_option, "test_parse_arguments_invalid_option", &tests_passed, &tests_failed, &total);
    run_test(test_parse_arguments_too_many_positionals, "test_parse_arguments_too_many_positionals", &tests_passed, &tests_failed, &total);
    run_test(test_parse_arguments_show_interface_only, "test_parse_arguments_show_interface_only", &tests_passed, &tests_failed, &total);
    run_test(test_eval_arguments_missing_interface, "test_eval_arguments_missing_interface", &tests_passed, &tests_failed, &total);
    run_test(test_eval_arguments_missing_ports, "test_eval_arguments_missing_ports", &tests_passed, &tests_failed, &total);
    run_test(test_eval_arguments_help_mode, "test_eval_arguments_help_mode", &tests_passed, &tests_failed, &total);
    run_test(test_eval_arguments_show_interface_mode, "test_eval_arguments_show_interface_mode", &tests_passed, &tests_failed, &total);

    // tests that rely on local interfaces
#ifdef HOME_TEST
    run_test(test_interfaces_output, "test_interfaces_output", &tests_passed, &tests_failed, &total);
    run_test(test_check_user_input_lo, "test_check_user_input_lo", &tests_passed, &tests_failed, &total);
    run_test(test_check_user_input_eth0, "test_check_user_input_eth0", &tests_passed, &tests_failed, &total);
    run_test(test_ipv4_address_from_eth0, "test_ipv4_aadress_form_eth0", &tests_passed, &tests_failed, &total);
    run_test(test_ipv6_address_from_eth0, "test_ipv6_aadress_form_eth0", &tests_passed, &tests_failed, &total);
    run_test(test_ipv4_address_from_lo, "test_ipv4_aadress_form_lo", &tests_passed, &tests_failed, &total);
    run_test(test_ipv6_address_from_lo, "test_ipv6_aadress_form_lo", &tests_passed, &tests_failed, &total);
#endif

    run_test(test_resolve_hostname_user_set_ipv4, "test_resolve_hostname_user_set_ipv4", &tests_passed, &tests_failed, &total);
    run_test(test_resolve_hostname_user_set_ipv6, "test_resolve_hostname_user_set_ipv6", &tests_passed, &tests_failed, &total);
    run_test(test_resolve_hostname_user_invalid_ipv4, "test_resolve_hostname_user_invalid_ipv4", &tests_passed, &tests_failed, &total);
    run_test(test_resolve_hostname_user_invalid_ipv6, "test_resolve_hostname_user_invalid_ipv6", &tests_passed, &tests_failed, &total);
    run_test(test_compare_ip, "test_compare_ip", &tests_passed, &tests_failed, &total);
    run_test(test_read_next_port_basic, "test_read_next_port_basic", &tests_passed, &tests_failed, &total);
    run_test(test_read_next_port_second_token, "test_read_next_port_second_token", &tests_passed, &tests_failed, &total);
    run_test(test_read_next_port_trailing_comma, "test_read_next_port_trailing_comma", &tests_passed, &tests_failed, &total);
    run_test(test_get_port_variants, "test_get_port_variants", &tests_passed, &tests_failed, &total);
    run_test(test_send_with_tcp_null_args, "test_send_with_tcp_null_args", &tests_passed, &tests_failed, &total);
    run_test(test_send_with_tcp_invalid_interface, "test_send_with_tcp_invalid_interface", &tests_passed, &tests_failed, &total);
    run_test(test_send_with_tcp_table_not_modified_on_init_fail, "test_send_with_tcp_table_not_modified_on_init_fail", &tests_passed, &tests_failed, &total);

    putchar('\n');

    total = tests_passed + tests_failed;

    if(tests_failed == 0) {
        printf("\033[32mALL TESTS PASSED (%d/%d)\033[0m\n", tests_passed, total);
    } else {
        printf("\033[31mTests passed: %d\n", tests_passed);
        printf("Tests failed: %d\n\033[0m", tests_failed);
    }

    return tests_failed;
}