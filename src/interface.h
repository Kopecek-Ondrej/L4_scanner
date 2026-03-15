#ifndef __INTERFACE_H
#define __INTERFACE_H

#include "cli_eval.h"
#include "address.h"

int print_interfaces();
int check_for_interface(Scanner_t *scanner, Source_address_t *source);

#endif // __INTERFACE_H