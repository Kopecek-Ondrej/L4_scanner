#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include <stdio.h>

//exit codes
#define EXIT_OK       0
#define ERR_CLI_ARG   2
#define ERR_NO_INTERFACE_FOUND 3
#define ERR_INVALID_HOST_ARG 4

#define ERR_SYS_INTERFACE 52
#define ERR_RESOLVE_HOST  53
#define ERR_SYS_MEM_ALLOC 54
#define ERR_NO_USABLE_ADDR_FOUND 55


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

#ifdef DEBUG
    #define DEBUG_PRINT(...) \
        do { \
            printf("[%s:%d %s]::", __FILE__, __LINE__, __func__); \
            printf(__VA_ARGS__); \
            printf("\n");\
        } while(0)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif
