#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "cli_parser.h"
#include "error_code.h"
#include "source.h"
}

TEST(SourceGetAvailablePortTest, ReturnsReservedPortAndValidSockets) {
	int tcp_fd = -1;
	int udp_fd = -1;

	uint32_t port = get_available_source_port(&tcp_fd, &udp_fd);

	ASSERT_GT(port, 0u);
	ASSERT_LE(port, 65535u);
	ASSERT_GE(tcp_fd, 0);
	ASSERT_GE(udp_fd, 0);

	struct sockaddr_in tcp_addr{};
	struct sockaddr_in udp_addr{};
	socklen_t tcp_len = sizeof(tcp_addr);
	socklen_t udp_len = sizeof(udp_addr);

	ASSERT_EQ(getsockname(tcp_fd, (struct sockaddr*)&tcp_addr, &tcp_len), 0);
	ASSERT_EQ(getsockname(udp_fd, (struct sockaddr*)&udp_addr, &udp_len), 0);

	EXPECT_EQ(ntohs(tcp_addr.sin_port), port);
	EXPECT_EQ(ntohs(udp_addr.sin_port), port);

	clean_dummy_fd(&tcp_fd, &udp_fd);
}

TEST(SourceResolveSourceTest, RejectsNullArguments) {
	Cli_Parser_t parser{};
	Source_address_t source{};

	EXPECT_EQ(resolve_source(nullptr, &source), ERR_CLI_ARG);
	EXPECT_EQ(resolve_source(&parser, nullptr), ERR_CLI_ARG);
}

TEST(SourceResolveSourceTest, RejectsMissingInterfaceName) {
	Cli_Parser_t parser{};
	Source_address_t source{};

	parser.interface = nullptr;
	EXPECT_EQ(resolve_source(&parser, &source), ERR_CLI_ARG);
}

TEST(SourceResolveSourceTest, RejectsNonexistentInterface) {
	Cli_Parser_t parser{};
	Source_address_t source{};

	char iface[] = "this-interface-does-not-exist";
	parser.interface = iface;

	EXPECT_EQ(resolve_source(&parser, &source), ERR_NO_INTERFACE_FOUND);
}

TEST(SourceResolveSourceTest, ResolvesLoopbackOrSkipsWhenUnavailable) {
	Cli_Parser_t parser{};
	Source_address_t source{};

	char iface[] = "lo";
	parser.interface = iface;

	int rc = resolve_source(&parser, &source);
	if(rc == ERR_NO_INTERFACE_FOUND) {
		GTEST_SKIP() << "Interface 'lo' not available in this environment";
	}

	ASSERT_EQ(rc, EXIT_OK);
	EXPECT_TRUE(source.is_ipv4 || source.is_ipv6 || source.is_local_ipv6);
}

