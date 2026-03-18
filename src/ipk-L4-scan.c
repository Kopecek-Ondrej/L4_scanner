#include <stdio.h>
#include <stdlib.h>

#include "cli_parser.h"
#include "cli_eval.h"
#include "error_code.h"
#include "interface.h"
#include "address.h"
#include "error_code.h"
#include "scanner.h"

static void print_answers(const Table_packet_t *table) {
	if (table == NULL || table->packets == NULL) {
		return;
	}

	for (int i = 0; i < table->size; i++) {
		const Packet_t *p = &table->packets[i];

		char ip[INET6_ADDRSTRLEN];
		ADDR_TO_STR((struct sockaddr *)&p->target_addr, ip);

		const char *proto = (p->proto == SCAN_TCP) ? "TCP" : "UDP";
		const char *status = "PENDING";
		switch (p->status) {
			case ST_OPEN: status = "OPEN"; break;
			case ST_CLOSED: status = "CLOSED"; break;
			case ST_FILTERED: status = "FILTERED"; break;
			case ST_PENDING: default: status = "PENDING"; break;
		}

		printf("%s %s:%u -> %s\n", proto, ip, p->port, status);
	}
}


int main(int argc, char* argv[]){
	Scanner_t scanner = {0};
	Arguments_t args = {0};
	Source_address_t source = {0};
	Destination_addresses_t destination = {0};
	Table_packet_t table = {0};
	int err = parse_arguments(argc, argv, &args);
	if(err != EXIT_OK){
		return err;
	}
	err = eval_arguments(&args, &scanner);
	if(err != EXIT_OK){
		return err;
	}

	switch(scanner.mode){
		case MODE_SHOW_INTERFACE:
		//getifaddrs
			err = print_interfaces();
			if(err != EXIT_OK) return err;

			break;
		case MODE_SHOW_HELP:
			print_help();
			break;
		case MODE_SCAN:
			err = check_for_interface(&scanner, &source);
			if(err != EXIT_OK) return err;
			err = resolve_hostname(&scanner, &destination);
			if(err != EXIT_OK) return err;
			err = scan_destinations(&scanner, &destination, &source, &table);
			if(err != EXIT_OK) return err;
			print_answers(&table);
			free_packets(table.packets);
			free_destination_addresses(&destination);
			break;
	}
	
	return 0;
}