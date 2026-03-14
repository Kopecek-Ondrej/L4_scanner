#include <stdio.h>
#include "test_cli.h"
#include "test_interface.h"



static void run_test(int (*test_func)(void), const char *name, int *tests_passed, int *tests_failed) {
    int rc = test_func();

    if (rc == 0) {
        (*tests_passed)++;
    } else {
        (*tests_failed)++;
        fprintf(stderr, "Test failed: %s\n", name);
    }
}



int main(void) {
    int tests_passed = 0;
    int tests_failed = 0;

    run_test(test_help_sets_mode, "test_help_sets_mode", &tests_passed, &tests_failed );
    run_test(test_missing_host_fails, "test_missing_host_fails",&tests_passed, &tests_failed);
    run_test(test_trailing_comma_is_error, "test_trailing_comma_is_error", &tests_passed, &tests_failed);

    //test that works at my computer
#ifdef HOME_TEST
    run_test(test_interfaces_output, "test_interfaces_output", &tests_passed, &tests_failed);
#endif

    int total = tests_passed + tests_failed;

    if (tests_failed == 0) {
        printf("\033[32mALL TESTS PASSED (%d/%d)\033[0m\n", tests_passed, total);
    } else {
        printf("\033[31mTests passed: %d\n", tests_passed);
        printf("Tests failed: %d\n\033[0m", tests_failed);
    }

    return tests_failed;
}