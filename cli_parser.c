#include <stdio.h>
#include <stdlib.h>
#include "cli_parser.h"
#include <stdbool.h>
#include <getopt.h>
#include <string.h>

#include "error_code.h"


int parse_arguments(int argc, char* argv[], arguments_t *args) {
	if(args == NULL){
		return ERR_CLI_ARG;
	}

	if(argc == 2){
		if(strcmp(argv[1], "--help") == 0){
			args->help = true;
		}else if(strcmp(argv[1], "-i") == 0){
			args->show_interface = true;
		}else if(strcmp(argv[1], "-h") == 0){
			args->help = true;
		}else{
			RETURN_ERROR(ERR_CLI_ARG, "Invalid Arguments");
		}
		args->arg_cnt = 2;
		// print_arguments(args);
		return EXIT_OK;
	}



	int opt = 0;
	while ((opt = getopt(argc, argv, "i:u:t:w:")) != -1) {
		args->arg_cnt++;
		switch (opt) {
			case 'i':
				args->interface = optarg;
				// args->show_interface = true;
				break;
			case 'u':
				args->u_ports = optarg;
				break;
			case 't':
				args->t_ports = optarg;
				break;
			case 'w':
				args->timeout = optarg;
				break;
			default:
				RETURN_ERROR(ERR_CLI_ARG, "Invalid option: -%c", opt);
		}
	}

	if (optind < argc) {
		args->hostname = argv[optind];
		optind++;
	}

	if (optind != argc) {
		RETURN_ERROR(ERR_CLI_ARG, "Too many positional arguments");
	}

	return EXIT_OK;
}

void print_arguments(const arguments_t *args) {
	if (args == NULL) {
		printf("arguments_t: (null)\n");
		return;
	}

	printf("interface: %s\n", args->interface ? args->interface : "(null)");
	printf("u_ports: %s\n", args->u_ports ? args->u_ports : "(null)");
	printf("t_ports: %s\n", args->t_ports ? args->t_ports : "(null)");
	printf("hostname: %s\n", args->hostname ? args->hostname : "(null)");
	printf("timeout: %s\n", args->timeout ? args->timeout : "(null)");
	printf("arg_cnt: %d\n", args->arg_cnt);
	printf("help: %s\n", args->help ? "true" : "false");
	printf("show_interface: %s\n", args->show_interface ? "true" : "false");
}


