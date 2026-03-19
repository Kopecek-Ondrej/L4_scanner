#ifndef __TEST_ADDRESS_H
#define __TEST_ADDRESS_H

int test_resolve_hostname_user_set_ipv4(void);
int test_resolve_hostname_user_set_ipv6(void);
int test_resolve_hostname_user_invalid_ipv4(void);
int test_resolve_hostname_user_invalid_ipv6(void);
int test_compare_ip(void);
int test_read_next_port_basic(void);
int test_read_next_port_second_token(void);
int test_read_next_port_trailing_comma(void);
int test_get_port_variants(void);

#endif //__TEST_ADDRESS_H