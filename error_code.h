#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include <stdio.h>

//exit codes
#define EXIT_OK       0
#define ERR_CLI_ARG   2

#define ERR_INTERFACE 52


void print_error(int error_code, const char *fmt, ...);

//disable prit in tests
#ifdef TEST_BUILD
    #define ERROR_PRINT(...) ((void)0)
#else
    #define ERROR_PRINT(...) print_error(__VA_ARGS__)
#endif

/* print + return code */
#define RETURN_ERROR(code, ...)      \
    do {                             \
        ERROR_PRINT((code), __VA_ARGS__); \
        return (code);               \
    } while (0)

#endif