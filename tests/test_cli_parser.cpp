#include <gtest/gtest.h>
#include <unistd.h>

extern "C" {
#include "cli_parser.h"
#include "error_code.h"
}

static void reset_getopt_state() {
	optind = 0;
	optarg = nullptr;
	opterr = 0;
	optopt = 0;
}

TEST(CliParserEvalPortsTest, ParsesSinglePortSuccessfully) {
	Ports_t ports{};
	int rc = eval_ports((char*)"80", &ports);

	EXPECT_EQ(rc, EXIT_OK);
	EXPECT_EQ(ports.type, SINGLE);
	EXPECT_EQ(ports.port_cnt, 1);
	EXPECT_EQ(ports.min, 80);
	EXPECT_EQ(ports.max, 80);
}

TEST(CliParserEvalPortsTest, ParsesReversedRangeSuccessfully) {
	Ports_t ports{};
	int rc = eval_ports((char*)"443-80", &ports);

	EXPECT_EQ(rc, EXIT_OK);
	EXPECT_EQ(ports.type, RANGE);
	EXPECT_EQ(ports.min, 80);
	EXPECT_EQ(ports.max, 443);
	EXPECT_EQ(ports.port_cnt, 364);
}

TEST(CliParserEvalPortsTest, ParsesCommaSeparatedPortsSuccessfully) {
	Ports_t ports{};
	char ports_input[] = "22,80,443,8080";
	int rc = eval_ports(ports_input, &ports);

	EXPECT_EQ(rc, EXIT_OK);
	EXPECT_EQ(ports.type, MULTIP);
	EXPECT_EQ(ports.port_cnt, 4);
	EXPECT_EQ(ports.ports_array, ports_input);
}

TEST(CliParserEvalPortsTest, RejectPointInPortArray) {
	Ports_t ports{};
	int rc = eval_ports((char*)"22.80", &ports);

	EXPECT_EQ(rc, ERR_CLI_ARG);
}

TEST(CliParserEvalPortsTest, RejectLettersInPortArray) {
	Ports_t ports{};
	int rc = eval_ports((char*)"22abs", &ports);

	EXPECT_EQ(rc, ERR_CLI_ARG);
    printf("PORT: %d\n\n",ports.min);
}

TEST(CliParserEvalPortsTest, RejectsTrailingCommaInPortList) {
	Ports_t ports{};
	int rc = eval_ports((char*)"22,80,", &ports);

	EXPECT_EQ(rc, ERR_CLI_ARG);
}

TEST(CliParserEvalPortsTest, RejectsPortAboveRange) {
	Ports_t ports{};
	int rc = eval_ports((char*)"65536", &ports);

	EXPECT_EQ(rc, ERR_PORT_RANGE);
}

TEST(CliParserEvalArgumentsTest, RequiresInterfaceInScanMode) {
	Arguments_t args{};
	Cli_Parser_t parser{};

	args.hostname = (char*)"example.com";
	args.t_ports = (char*)"80";

	int rc = eval_arguments(&args, &parser);
	EXPECT_EQ(rc, ERR_CLI_ARG);
}

TEST(CliParserEvalArgumentsTest, SetsDefaultsAndScanMode) {
	Arguments_t args{};
	Cli_Parser_t parser{};

	args.interface = (char*)"lo";
	args.hostname = (char*)"localhost";
	args.t_ports = (char*)"80";

	int rc = eval_arguments(&args, &parser);

	EXPECT_EQ(rc, EXIT_OK);
	EXPECT_EQ(parser.mode, MODE_SCAN);
	EXPECT_EQ(parser.timeout, DEFAULT_TIMEOUT);
	EXPECT_TRUE(parser.tcp_use);
	EXPECT_FALSE(parser.udp_use);
	EXPECT_STREQ(parser.interface, "lo");
	EXPECT_STREQ(parser.hostname, "localhost");
}

TEST(CliParserParseArgumentsTest, ParsesLongHelpFlag) {
	reset_getopt_state();
	Arguments_t args{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "--help";
	char* argv[] = {arg0, arg1};

	int rc = parse_arguments(2, argv, &args);

	EXPECT_EQ(rc, EXIT_OK);
	EXPECT_TRUE(args.help);
	EXPECT_EQ(args.arg_cnt, 2);
}

TEST(CliParserParseArgumentsTest, RejectExtraUnknowFlag){
    reset_getopt_state();
    Arguments_t args{};
    char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char arg2[] = "eth0";
	char arg3[] = "-h";
	char arg4[] = "90";
	char* argv[] = {arg0, arg1, arg2, arg3, arg4};
    
    int rc = parse_arguments(5, argv, &args);
    EXPECT_EQ(rc,ERR_CLI_ARG );

}

TEST(CliParserParseArgumentsTest, RejectsExtraPositionalArguments) {
	reset_getopt_state();
	Arguments_t args{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char arg2[] = "eth0";
	char arg3[] = "example.com";
	char arg4[] = "extra";
	char* argv[] = {arg0, arg1, arg2, arg3, arg4};

	int rc = parse_arguments(5, argv, &args);
	EXPECT_EQ(rc, ERR_CLI_ARG);
}

TEST(CliParserCombinedTest, HelpModeFromLongFlag) {
	reset_getopt_state();
	Arguments_t args{};
	Cli_Parser_t parser{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "--help";
	char* argv[] = {arg0, arg1};

	int parse_rc = parse_arguments(2, argv, &args);
	ASSERT_EQ(parse_rc, EXIT_OK);

	int eval_rc = eval_arguments(&args, &parser);
	EXPECT_EQ(eval_rc, EXIT_OK);
	EXPECT_EQ(parser.mode, MODE_SHOW_HELP);
}

TEST(CliParserCombinedTest, ShowInterfaceModeFromShortIOnly) {
	reset_getopt_state();
	Arguments_t args{};
	Cli_Parser_t parser{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char* argv[] = {arg0, arg1};

	int parse_rc = parse_arguments(2, argv, &args);
	ASSERT_EQ(parse_rc, EXIT_OK);

	int eval_rc = eval_arguments(&args, &parser);
	EXPECT_EQ(eval_rc, EXIT_OK);
	EXPECT_EQ(parser.mode, MODE_SHOW_INTERFACE);
}

TEST(CliParserCombinedTest, RejectsScanWithoutHost) {
	reset_getopt_state();
	Arguments_t args{};
	Cli_Parser_t parser{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char arg2[] = "eth0";
	char arg3[] = "-t";
	char arg4[] = "80";
	char* argv[] = {arg0, arg1, arg2, arg3, arg4};

	int parse_rc = parse_arguments(5, argv, &args);
	ASSERT_EQ(parse_rc, EXIT_OK);

	int eval_rc = eval_arguments(&args, &parser);
	EXPECT_EQ(eval_rc, ERR_CLI_ARG);
}

TEST(CliParserCombinedTest, RejectsScanWithoutPorts) {
	reset_getopt_state();
	Arguments_t args{};
	Cli_Parser_t parser{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char arg2[] = "eth0";
	char arg3[] = "example.com";
	char* argv[] = {arg0, arg1, arg2, arg3};

	int parse_rc = parse_arguments(4, argv, &args);
	ASSERT_EQ(parse_rc, EXIT_OK);

	int eval_rc = eval_arguments(&args, &parser);
	EXPECT_EQ(eval_rc, ERR_CLI_ARG);
}

TEST(CliParserCombinedTest, RejectsInvalidTimeoutValue) {
	reset_getopt_state();
	Arguments_t args{};
	Cli_Parser_t parser{};
	char arg0[] = "ipk-L4-scan";
	char arg1[] = "-i";
	char arg2[] = "eth0";
	char arg3[] = "-t";
	char arg4[] = "80";
	char arg5[] = "-w";
	char arg6[] = "0";
	char arg7[] = "example.com";
	char* argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7};

	int parse_rc = parse_arguments(8, argv, &args);
	ASSERT_EQ(parse_rc, EXIT_OK);

	int eval_rc = eval_arguments(&args, &parser);
	EXPECT_EQ(eval_rc, ERR_CLI_ARG);
}
