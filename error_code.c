#include <stdarg.h>
#include <stdio.h>
#include "error_code.h"

void print_error(int errorCode, const char* message, ...) {
	va_list args;
	va_start(args, message);
	fprintf(stderr, "Error %d: ", errorCode);
	vfprintf(stderr, message, args);
	fprintf(stderr, "\n");
	va_end(args);
}