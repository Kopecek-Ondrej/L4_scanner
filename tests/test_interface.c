#include <string.h>
#include <stdio.h>
#include "test_interface.h"
#include "helper.h"
#include "interface.h"
#include "error_code.h"

int test_interfaces_output(void)
{
    char output[256];

    capture_stdout(output, sizeof(output), (void (*)(void))print_interfaces);

    if (strstr(output, "lo") == NULL) {
        fprintf(stderr, "FAIL: lo not printed\n");
        return 1;
    }

    if (strstr(output, "eth0") == NULL) {
        fprintf(stderr, "FAIL: eth0 not printed\n");
        return 1;
    }

    return 0;
}

int test_check_user_input_lo(void){
    Scanner_t scanner = {0};
    scanner.interface = "lo";

    int rc = check_for_interface(&scanner);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}

int test_check_user_input_eth0(void){
    Scanner_t scanner = {0};
    scanner.interface = "eth0";

    int rc = check_for_interface(&scanner);
    ASSERT_EQ_INT(EXIT_OK, rc, "usr input matches host machine network interface");
    return 0;
}