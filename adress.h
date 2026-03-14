#ifndef __ADRESS_H_
#define __ADRESS_H_

#include <stddef.h>

/* Resolves hostname to IPv4 string. Returns 0 on success, -1 on error. */
int resolve_hostname(const char *hostname, char *out_ip, size_t out_size);

#endif // __ADRESS_H_