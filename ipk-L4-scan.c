#include <stdio.h>
#include <stdlib.h>

#include "cli_parser.h"
#include "cli_eval.h"
#include "error_code.h"
#include "interface.h"


int main(int argc, char* argv[]){
	Scanner_t scanner = {0};
	arguments_t args = {0};
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
			err = check_for_interface(&scanner);
			if(err != EXIT_OK) return err;
			
			break;
	}
	
	return 0;
}