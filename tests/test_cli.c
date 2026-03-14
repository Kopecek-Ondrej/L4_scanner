#include <stdio.h>
#include <string.h>
#include "cli_parser.h"
#include "cli_eval.h"
#include "error_code.h"
#include "test_cli.h"


int test_help_sets_mode(void) {
    char *argv[] = {"prog", "--help"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    arguments_t args = {0};
    Scanner_t scanner = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments help");
    ASSERT_EQ_INT(1, args.help, "args.help set");

    rc = eval_arguments(&args, &scanner);
    ASSERT_EQ_INT(EXIT_OK, rc, "eval_arguments help");
    ASSERT_EQ_INT(MODE_SHOW_HELP, scanner.mode, "scanner.mode help");
    return 0;
}

int test_missing_host_fails(void) {
    char *argv[] = {"prog", "-t", "22"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    arguments_t args = {0};
    Scanner_t scanner = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments missing host");

    rc = eval_arguments(&args, &scanner);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments missing host error");
    return 0;
}

int test_trailing_comma_is_error(void) {
    char *argv[] = {"prog", "-u", "22," , "host"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    arguments_t args = {0};
    Scanner_t scanner = {0};

    int rc = parse_arguments(argc, argv, &args);
    ASSERT_EQ_INT(EXIT_OK, rc, "parse_arguments trailing comma");

    rc = eval_arguments(&args, &scanner);
    ASSERT_EQ_INT(ERR_CLI_ARG, rc, "eval_arguments trailing comma error");
    return 0;
}
//todo:: more relevant tests

