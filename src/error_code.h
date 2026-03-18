#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include <stdio.h>

#ifdef DEBUG 
#include <time.h>
#endif // DEBUG

//exit codes
#define EXIT_OK       0
#define ERR_CLI_ARG   2
#define ERR_NO_INTERFACE_FOUND 3
#define ERR_INVALID_HOST_ARG 4
#define ERR_NO_ARGUMENTS 5
#define ERR_PORT_RANGE 6

#define ERR_SYS_INTERFACE 52
#define ERR_RESOLVE_HOST  53
#define ERR_SYS_MEM_ALLOC 54
#define ERR_NO_USABLE_ADDR_FOUND 55
#define ERR_SOCK_INIT 56
#include <stdarg.h>
#include <stddef.h>

int any_null(size_t count, ...);

#define RETURN_IF_NULL(code, ...)                          \
    do {                                                   \
        void *args[] = { __VA_ARGS__ };                    \
        for (size_t i = 0; i < sizeof(args)/sizeof(args[0]); i++) { \
            if (args[i] == NULL) {                         \
                RETURN_ERROR(code, "NULL argument detected"); \
            }                                              \
        }                                                  \
    } while (0)

void print_error(int error_code, const char *fmt, ...);

//disable prit in tests
#ifdef TEST_BUILD
    #define ERROR_PRINT(...) ((void)0)
#else
    #define ERROR_PRINT(...) print_error(__VA_ARGS__)
#endif

#ifdef DEBUG
    #define DEBUG_PRINT(...) \
        do { \
            printf("\t[%s:%d %s]::", __FILE__, __LINE__, __func__); \
            printf(__VA_ARGS__); \
            printf("\n");\
        } while(0)
#else
    #define DEBUG_PRINT(...) do {} while(0)
#endif //DEBUG

#ifdef DEBUG_T
        #define DEBUG_TIME(label, stmt)                                                \
            do {                                                                       \
                struct timespec __start, __end;                                        \
                clock_gettime(CLOCK_MONOTONIC, &__start);                              \
                stmt;                                                                  \
                clock_gettime(CLOCK_MONOTONIC, &__end);                                \
                double __elapsed =                                                     \
                    (__end.tv_sec - __start.tv_sec) +                                  \
                    (__end.tv_nsec - __start.tv_nsec) / 1000000000.0;                  \
                fprintf(stderr, "\t[TIME] %s: %.6f s\n", (label), __elapsed);            \
            } while (0)
#else
    #define DEBUG_TIME(label, stmt)                                                \
    do {                                                                       \
        stmt;                                                                  \
    } while (0)
#endif //DEBUG_TIME


/* print + return code */
#define RETURN_ERROR(code, ...)      \
    do {                             \
        ERROR_PRINT((code), __VA_ARGS__); \
        return (code);               \
    } while (0)

#endif //__ERROR_CODE_H