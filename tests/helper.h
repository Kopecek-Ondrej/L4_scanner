#ifndef __HELPER_H_
#define __HELPER_H_

#include <unistd.h>
#include <stdio.h>
#include <string.h>

int capture_stdout(char *buffer, size_t size, void (*func)(void));

#define ASSERT_EQ_INT(expected, actual, msg)                                  \
    do {                                                                      \
        if ((expected) != (actual)) {                                         \
            fprintf(stderr, "FAIL: %s (expected %d, got %d)\n",               \
                    (msg), (expected), (actual));                             \
            return 1;                                                         \
        }                                                                     \
    } while (0)

#endif // __HELPER_H_