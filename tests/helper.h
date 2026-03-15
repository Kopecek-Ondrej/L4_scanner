#ifndef __HELPER_H_
#define __HELPER_H_

#include <unistd.h>
#include <stdio.h>
#include <string.h>

int capture_stdout(char *buffer, size_t size, void (*func)(void));

#define ASSERT_EQ_INT(expected, actual, msg)                                  \
    do{                                                                      \
        if((expected) != (actual)) {                                         \
            fprintf(stderr, "FAIL: %s (expected %d, got %d)\n",               \
                    (msg), (expected), (actual));                             \
            return 1;                                                         \
        }                                                                     \
    }while(0)


#define ASSERT_EQ_STR(expected, actual, msg)                        \
    do{                                                            \
        const char *exp_ = (expected);                              \
        const char *act_ = (actual);                                \
        if (strcmp(exp_, act_) != 0) {                              \
            fprintf(stderr,                                         \
                    "FAIL: %s (expected \"%s\", got \"%s\")\n",     \
                    (msg), exp_, act_);                             \
            return 1;                                               \
        }                                                           \
    }while(0)                                                     \
    
#endif // __HELPER_H_