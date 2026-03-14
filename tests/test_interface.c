#include <string.h>
#include <stdio.h>
#include "test_interface.h"
#include "helper.h"
#include "interface.h"

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