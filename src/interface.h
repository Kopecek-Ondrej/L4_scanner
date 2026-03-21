#ifndef __INTERFACE_H
#define __INTERFACE_H

#include "cli_eval.h"
#include "address.h"

int print_interfaces();
int check_for_interface(Parser_t *parser, Source_address_t *source);

#endif // __INTERFACE_H