/**
 * 	Author: Ondřej Kopeček
 * 	login: xkopeco00
 *
 *	Project: L4-scanner
 */

#include "error_code.h"
#include <stdarg.h>
#include <stdio.h>

void print_error(int errorCode, const char* message, ...) {
    va_list args;
    va_start(args, message);
    fprintf(stderr, "Error %d: ", errorCode);
    vfprintf(stderr, message, args);
    fprintf(stderr, "\n");
    va_end(args);
}

int any_null(size_t count, ...) {
    va_list args;
    va_start(args, count);

    for(size_t i = 0; i < count; i++) {
        void* ptr = va_arg(args, void*);
        if(ptr == NULL) {
            va_end(args);
            return 1; // found NULL
        }
    }

    va_end(args);
    return 0; // all good
}