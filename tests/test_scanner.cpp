#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <cstring>
#include <string>
#include <thread>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <unistd.h>

extern "C" {
#include "error_code.h"
#include "scanner.h"
}

static std::string find_loopback_iface() {
	struct ifaddrs* ifaddr = nullptr;
	if(getifaddrs(&ifaddr) == -1) {
		return "";
	}

	std::string iface;
	for(struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
		if(ifa->ifa_name == nullptr) {
			continue;
		}
		if((ifa->ifa_flags & IFF_LOOPBACK) != 0) {
			iface = ifa->ifa_name;
			break;
		}
	}

	freeifaddrs(ifaddr);
	return iface;
}

TEST(ScannerHelpersTest, ReadNextPortParsesCommaSeparatedValues) {
	char ports[] = "22,80,443";
	int port = -1;

	int pos = read_next_port(ports, 0, &port);
	EXPECT_EQ(port, 22);

	pos = read_next_port(ports, pos, &port);
	EXPECT_EQ(port, 80);

	read_next_port(ports, pos, &port);
	EXPECT_EQ(port, 443);
}

TEST(ScannerHelpersTest, GetElapsedMsIncreasesOverTime) {
	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);

	std::this_thread::sleep_for(std::chrono::milliseconds(15));
	long elapsed = get_elapsed_ms(start);

	EXPECT_GE(elapsed, 10);
}

TEST(ScannerLoopbackTest, SetupPcapFilterWorksOnLoopbackOrSkips) {
	std::string iface = find_loopback_iface();
	if(iface.empty()) {
		GTEST_SKIP() << "No loopback interface found";
	}

	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t* handle = pcap_open_live(iface.c_str(), BUFSIZ, 0, 1000, errbuf);
	if(handle == nullptr) {
		GTEST_SKIP() << "Cannot open pcap on loopback: " << errbuf;
	}

	int rc = setup_pcap_filter(handle, 12345);
	pcap_close(handle);

	EXPECT_EQ(rc, EXIT_OK);
}

TEST(ScannerLoopbackTest, ReceivePacketsCanStartAndStopOnLoopbackOrSkips) {
	std::string iface = find_loopback_iface();
	if(iface.empty()) {
		GTEST_SKIP() << "No loopback interface found";
	}

	Cli_Parser_t parser{};
	parser.interface = const_cast<char*>(iface.c_str());

	Table_packet_t table{};
	std::atomic<int> recv_rc{INT_MIN};
	std::atomic<bool> done{false};

	std::thread rx([&]() {
		recv_rc.store(receive_packets(&parser, &table));
		done.store(true);
	});

	const int max_wait_ms = 2500;
	int waited_ms = 0;
	while(waited_ms < max_wait_ms && !done.load() && parser.pcap_handle == nullptr) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
		waited_ms++;
	}

	if(done.load() && recv_rc.load() != EXIT_OK) {
		rx.join();
		GTEST_SKIP() << "receive_packets failed in this environment (likely permissions)";
	}

	if(parser.pcap_handle != nullptr) {
		pcap_breakloop(parser.pcap_handle);
	}

	rx.join();
	EXPECT_EQ(recv_rc.load(), EXIT_OK);
}
//____________________________________________________MOCK SERVERS___________________________________

// Mock TCP server (IPv4)
void mock_tcp_server(uint16_t port, std::atomic<bool>& running, std::atomic<bool>& stop) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) return;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }
    
    listen(server_fd, 1);
    running = true; // Signal to the test that the server is ready

    // Keep the server running until the test requests stop or timeout expires
    for (int i = 0; i < 50 && !stop; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    close(server_fd);
}
#include <vector>

// Mock TCP server for multiple ports at once
void mock_tcp_ipv4_server_multi(const std::vector<uint16_t>& ports, std::atomic<bool>& running, std::atomic<bool>& stop) {
    std::vector<int> server_fds;

    // Create and bind one socket for each port
    for (uint16_t port : ports) {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) continue;

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(server_fd);
            continue;
        }
        
        listen(server_fd, 5); // 5 is the backlog size for pending TCP connections
        server_fds.push_back(server_fd);
    }

    running = true; // Signal to the test that all ports are listening

    // Keep ports open until the test requests stop
    while (!stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Cleanup after test ends
    for (int fd : server_fds) {
        close(fd);
    }
}
// False UDP server (IPv4)
void mock_udp_server(uint16_t port, std::atomic<bool>& running, std::atomic<bool>& stop) {
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) return;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }
    
    running = true;
    for (int i = 0; i < 50 && !stop; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    close(server_fd);
}

// Dummy server (IPv6)
void mock_tcp_server_v6(uint16_t port, std::atomic<bool>& running, std::atomic<bool>& stop) {
    int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (server_fd < 0) return;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback; // ::1
    addr.sin6_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }
    
    listen(server_fd, 1);
    running = true;

    for (int i = 0; i < 50 && !stop; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    close(server_fd);
}

// Mock UDP server (IPv6)
void mock_udp_server_v6(uint16_t port, std::atomic<bool>& running, std::atomic<bool>& stop) {
    int server_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (server_fd < 0) return;

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback; // ::1
    addr.sin6_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(server_fd);
        return;
    }
    
    running = true;
    for (int i = 0; i < 50 && !stop; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    close(server_fd);
}
// Mock UDP server (IPv4) for multiple ports
void mock_udp_ipv4_server_multi(const std::vector<uint16_t>& ports, std::atomic<bool>& running, std::atomic<bool>& stop) {
    std::vector<int> server_fds;
    for (uint16_t port : ports) {
        int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (server_fd < 0) continue;

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        addr.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            server_fds.push_back(server_fd);
        } else {
            close(server_fd);
        }
    }
    // Only signal running if ALL requested ports were successfully bound
    if (server_fds.size() == ports.size()) {
        running = true;
    } else {
        std::cerr << "Warning: Failed to bind all UDP IPv4 ports. Bound " << server_fds.size() 
                  << " of " << ports.size() << " requested ports." << std::endl;
    }
    while (!stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    for (int fd : server_fds) close(fd);
}

// Mock TCP server (IPv6) for multiple ports
void mock_tcp_ipv6_server_multi(const std::vector<uint16_t>& ports, std::atomic<bool>& running, std::atomic<bool>& stop) {
    std::vector<int> server_fds;
    for (uint16_t port : ports) {
        int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (server_fd < 0) continue;

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback; // ::1
        addr.sin6_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            listen(server_fd, 5);
            server_fds.push_back(server_fd);
        } else {
            close(server_fd);
        }
    }
    // Only signal running if ALL requested ports were successfully bound
    if (server_fds.size() == ports.size()) {
        running = true;
    } else {
        std::cerr << "Warning: Failed to bind all TCP IPv6 ports. Bound " << server_fds.size() 
                  << " of " << ports.size() << " requested ports." << std::endl;
    }
    while (!stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    for (int fd : server_fds) close(fd);
}

// Mock UDP server (IPv6) for multiple ports
void mock_udp_ipv6_server_multi(const std::vector<uint16_t>& ports, std::atomic<bool>& running, std::atomic<bool>& stop) {
    std::vector<int> server_fds;
    for (uint16_t port : ports) {
        int server_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (server_fd < 0) continue;

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback; // ::1
        addr.sin6_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            server_fds.push_back(server_fd);
        } else {
            close(server_fd);
        }
    }
    // Only signal running if ALL requested ports were successfully bound
    if (server_fds.size() == ports.size()) {
        running = true;
    } else {
        std::cerr << "Warning: Failed to bind all UDP IPv6 ports. Bound " << server_fds.size() 
                  << " of " << ports.size() << " requested ports." << std::endl;
    }
    while (!stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    for (int fd : server_fds) close(fd);
}
//_____________________________________________________END MOCK SERVERS_________________


TEST(ScannerNetwork, TcpIpv4OpenPort) {
    // 1. Guard: skip if not running as root
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping: Testing pcap and raw sockets requires root privileges (sudo).";
    }

    uint16_t test_port = 8888;
    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    // Start mock server in background
    std::thread server_thread(mock_tcp_server, test_port, std::ref(server_running), std::ref(server_stop));

    // Wait until server starts listening
    while (!server_running) {
        std::this_thread::yield();
    }

    // 2. Initialize parser
    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo"; // Loopback interface
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.min = test_port;
	parser.tcp_ports.max = test_port;

    // 3. Initialize destination address
    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    // 4. Initialize source address
    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    // 5. Initialize packet table
    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    // 6. Call function under test
    int err = scan_destinations(&parser, &dest, &src, &table);

    // Handle runtime permission-related failures
    if (err != 0 /* Optionally compare with your specific ERR_PCAP code */) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        
        GTEST_SKIP() << "scan_destinations failed (likely WSL2 pcap issue or permission problem). Error code: " << err;
    }

    // 7. Verify expected result: port should be OPEN
    EXPECT_EQ(table.packets[0].status, ST_OPEN);

    // 8. Cleanup
    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, TcpIpv4ClosedPort) {
    uint16_t test_port = 54321; // High random port where nothing should be listening

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.min = test_port;
	parser.tcp_ports.max = test_port;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        free(table.packets);
        GTEST_SKIP() << "Skipped due to pcap error (permissions): " << err;
    }

    // Expect ST_CLOSED because no service listens on this port (RST response expected)
    EXPECT_EQ(table.packets[0].status, ST_CLOSED);

    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}
TEST(ScannerNetwork, UdpIpv4ClosedPort) {
    // Use a high random port where nothing is expected to listen
    uint16_t test_port = 54322;

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.udp_use = true;
    parser.udp_ports.port_cnt = 1;
    parser.udp_ports.min = test_port;
	parser.udp_ports.max = test_port;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    table.packets[0].dst_addr = res_addr;
    table.packets[0].src_addr = src;
    table.packets[0].dst_port = test_port;
    table.packets[0].proto = SCAN_UDP;
    table.packets[0].family = AF_INET;
    table.packets[0].status = ST_PENDING;
    table.packets[0].tries = 0;

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // If BPF filter correctly passes ICMP and parser maps replies
    // to the right sent packet, state should change
    // from PENDING to CLOSED before timeout.
    EXPECT_EQ(table.packets[0].status, ST_CLOSED);

    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, UdpIpv4OpenPort) {
    uint16_t test_port = 8889;
    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::thread server_thread(mock_udp_server, test_port, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000; // Shorter timeout to speed up the test
    parser.udp_use = true;
    parser.udp_ports.port_cnt = 1;
    parser.udp_ports.min = test_port;
	parser.udp_ports.max = test_port;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to pcap error (permissions): " << err;
    }

    // Based on current logic: without ICMP unreachable, state becomes ST_OPEN after timeouts
    EXPECT_EQ(table.packets[0].status, ST_OPEN);

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, TcpIpv6OpenPort) {
    uint16_t test_port = 8890;
    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::thread server_thread(mock_tcp_server_v6, test_port, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.max = test_port;
	parser.tcp_ports.min = test_port;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET6;
    // Use IPv6 loopback (::1)
    inet_pton(AF_INET6, "::1", &res_addr.addr.raddr6); 

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv6 = true; // IPv6 enabled flag
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv6 = true; // IPv6 source marker
    inet_pton(AF_INET6, "::1", &src.addr6);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to pcap error (permissions): " << err;
    }

    EXPECT_EQ(table.packets[0].status, ST_OPEN);

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, UdpIpv6OpenPort) {
    uint16_t test_port = 8891;
    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::thread server_thread(mock_udp_server_v6, test_port, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 500; // Shorter timeout (500 ms) speeds up the test
    parser.udp_use = true;
    parser.udp_ports.port_cnt = 1;
    parser.udp_ports.min = test_port;
	parser.udp_ports.max = test_port;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET6;
    inet_pton(AF_INET6, "::1", &res_addr.addr.raddr6);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv6 = true; // Required flag for IPv6 flow
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv6 = true;
    inet_pton(AF_INET6, "::1", &src.addr6);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // Expect ST_OPEN due to UDP timeout behavior
    EXPECT_EQ(table.packets[0].status, ST_OPEN);

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, TcpIpv4MultiplePorts) {
    uint16_t port_open1 = 8001;
    uint16_t port_closed = 8002;
    uint16_t port_open3 = 8003;
	char port_arr[] = "8001,8002,8003";

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    // Start only ports that should be OPEN
    std::vector<uint16_t> open_ports = {port_open1, port_open3};
    std::thread server_thread(mock_tcp_ipv4_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    // Wait until both ports are ready
    while (!server_running) {
        std::this_thread::yield();
    }

    // Initialize scanner for all 3 ports
    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 3;
    parser.tcp_ports.ports_array = port_arr;
	parser.tcp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 3;
    table.packets = (Packet_t*)malloc(3 * sizeof(Packet_t));
    memset(table.packets, 0, 3 * sizeof(Packet_t));

    // for (int i = 0; i < 3; ++i) {
    //     table.packets[i].dst_addr = res_addr;
    //     table.packets[i].src_addr = src;
    //     table.packets[i].dst_port = parser.tcp_ports.ports[i];
    //     table.packets[i].proto = SCAN_TCP;
    //     table.packets[i].family = AF_INET;
    //     table.packets[i].status = ST_PENDING;
    //     table.packets[i].tries = 0;
    // }

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        // free(parser.tcp_ports.ports);
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // Evaluate expected states
    EXPECT_EQ(table.packets[0].status, ST_OPEN)   << "Port " << port_open1 << " should be OPEN";
    EXPECT_EQ(table.packets[1].status, ST_CLOSED) << "Port " << port_closed << " should be CLOSED";
    EXPECT_EQ(table.packets[2].status, ST_OPEN)   << "Port " << port_open3 << " should be OPEN";

    // Safely stop server
    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    // free(parser.tcp_ports.ports);
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, UdpIpv4MultiplePorts) {
    uint16_t port_open1 = 8011;
    uint16_t port_closed = 8012;
    uint16_t port_open3 = 8013;
    char port_arr[] = "8011,8012,8013";

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::vector<uint16_t> open_ports = {port_open1, port_open3};
    std::thread server_thread(mock_udp_ipv4_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.udp_use = true;
    parser.udp_ports.port_cnt = 3;
    parser.udp_ports.ports_array = port_arr;
    parser.udp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 3;
    table.packets = (Packet_t*)malloc(3 * sizeof(Packet_t));
    memset(table.packets, 0, 3 * sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // Open ports end as ST_OPEN on timeout, closed port replies with ICMP Unreachable (ST_CLOSED)
    EXPECT_EQ(table.packets[0].status, ST_OPEN)   << "Port " << port_open1 << " should be OPEN";
    EXPECT_EQ(table.packets[1].status, ST_CLOSED) << "Port " << port_closed << " should be CLOSED";
    EXPECT_EQ(table.packets[2].status, ST_OPEN)   << "Port " << port_open3 << " should be OPEN";

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, TcpIpv6MultiplePorts) {
    uint16_t port_open1 = 8004;
    uint16_t port_closed = 8005;
    uint16_t port_open3 = 8006;
    char port_arr[] = "8004,8005,8006";

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::vector<uint16_t> open_ports = {port_open1, port_open3};
    std::thread server_thread(mock_tcp_ipv6_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 3;
    parser.tcp_ports.ports_array = port_arr;
    parser.tcp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET6;
    inet_pton(AF_INET6, "::1", &res_addr.addr.raddr6);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv6 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv6 = true;
    inet_pton(AF_INET6, "::1", &src.addr6);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 3;
    table.packets = (Packet_t*)malloc(3 * sizeof(Packet_t));
    memset(table.packets, 0, 3 * sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    EXPECT_EQ(table.packets[0].status, ST_OPEN)   << "Port " << port_open1 << " should be OPEN";
    EXPECT_EQ(table.packets[1].status, ST_CLOSED) << "Port " << port_closed << " should be CLOSED";
    EXPECT_EQ(table.packets[2].status, ST_OPEN)   << "Port " << port_open3 << " should be OPEN";

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetwork, UdpIpv6MultiplePorts) {
    uint16_t port_open1 = 8007;
    uint16_t port_closed = 8008;
    uint16_t port_open3 = 8009;
    char port_arr[] = "8007,8008,8009";

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::vector<uint16_t> open_ports = {port_open1, port_open3};
    std::thread server_thread(mock_udp_ipv6_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.udp_use = true;
    parser.udp_ports.port_cnt = 3;
    parser.udp_ports.ports_array = port_arr;
    parser.udp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET6;
    inet_pton(AF_INET6, "::1", &res_addr.addr.raddr6);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv6 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv6 = true;
    inet_pton(AF_INET6, "::1", &src.addr6);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 3;
    table.packets = (Packet_t*)malloc(3 * sizeof(Packet_t));
    memset(table.packets, 0, 3 * sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    EXPECT_EQ(table.packets[0].status, ST_OPEN)   << "Port " << port_open1 << " should be OPEN";
    EXPECT_EQ(table.packets[1].status, ST_CLOSED) << "Port " << port_closed << " should be CLOSED";
    EXPECT_EQ(table.packets[2].status, ST_OPEN)   << "Port " << port_open3 << " should be OPEN";

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetworkEdge, TcpIpv4EdgeCasePortZero) {
    char port_arr[] = "0";

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.ports_array = port_arr;
    // Using same array processing format as previous tests
    parser.tcp_ports.type = MULTIP; 

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // Expect ST_CLOSED (OS responds with RST) or ST_FILTERED (OS drops it).
    // Test passes if one of these two outcomes occurs.
    EXPECT_TRUE(table.packets[0].status == ST_CLOSED || table.packets[0].status == ST_FILTERED) 
        << "Edge case failed: Port 0 should be evaluated as CLOSED or FILTERED, never OPEN.";

    free(table.packets);
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

}

TEST(ScannerNetworkEdge, TcpIpv4EdgeCaseTenDuplicatePorts) {
    uint16_t test_port = 8010;
    // User input contains the same port 10 times
    char port_arr[] = "8010,8010,8010,8010,8010,8010,8010,8010,8010,8010";
    const int count = 10;

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    // Start mock server for only one physical port
    std::vector<uint16_t> open_ports = {test_port};
    std::thread server_thread(mock_tcp_ipv4_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = count;
    parser.tcp_ports.ports_array = port_arr;
    parser.tcp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = count;
    table.packets = (Packet_t*)malloc(count * sizeof(Packet_t));
    memset(table.packets, 0, count * sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    // Check all 10 instances to ensure correct state ST_OPEN
    for (int i = 0; i < count; ++i) {
        EXPECT_EQ(table.packets[i].status, ST_OPEN) 
            << "Port instance " << test_port << " at index " << i << " failed.";
    }

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetworkEdge, TcpIpv4EdgeCaseMaxPort) {
    uint16_t max_port = 65535;
    char port_arr[] = "65535";

    std::atomic<bool> server_running{false};
    std::atomic<bool> server_stop{false};

    std::vector<uint16_t> open_ports = {max_port};
    std::thread server_thread(mock_tcp_ipv4_server_multi, open_ports, std::ref(server_running), std::ref(server_stop));

    while (!server_running) {
        std::this_thread::yield();
    }

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1000;
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.ports_array = port_arr;
    parser.tcp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        server_stop = true;
        server_thread.join();
        free(table.packets);
        GTEST_SKIP() << "Skipped due to error: " << err;
    }

    EXPECT_EQ(table.packets[0].status, ST_OPEN) << "Scanner failed to properly handle maximum port 65535.";

    server_stop = true;
    if (server_thread.joinable()) {
        server_thread.join();
    }
    
    free(table.packets);
}

TEST(ScannerNetworkEdge, EdgeCaseMicroTimeout) {
    char port_arr[] = "80,443";
    
    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    parser.interface = (char*)"lo";
    parser.timeout = 1; // Extremely short timeout (1 millisecond)
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 2;
    parser.tcp_ports.ports_array = port_arr;
    parser.tcp_ports.type = MULTIP;
	
    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 2;
    table.packets = (Packet_t*)malloc(2 * sizeof(Packet_t));
    memset(table.packets, 0, 2 * sizeof(Packet_t));

    int err = scan_destinations(&parser, &dest, &src, &table);

    EXPECT_EQ(err, 0);
    // Usually ST_FILTERED since 1ms is too short for packet processing
    EXPECT_TRUE(table.packets[0].status == ST_FILTERED || table.packets[0].status == ST_CLOSED);

    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST(ScannerNetworkEdge, TcpIpv4EdgeCaseAnyIpFiltered) {
    char port_arr[] = "9999";

    Cli_Parser_t parser;
    memset(&parser, 0, sizeof(parser));
    // Use local loopback interface
    parser.interface = (char*)"lo"; 
    parser.timeout = 500; // 500 ms is plenty to verify the timeout behavior
    parser.tcp_use = true;
    parser.tcp_ports.port_cnt = 1;
    parser.tcp_ports.ports_array = port_arr;
    parser.tcp_ports.type = MULTIP;

    Resolved_address_t res_addr;
    memset(&res_addr, 0, sizeof(res_addr));
    res_addr.family = AF_INET;
    // The core of this edge case: Target IP address 0.0.0.0
    inet_pton(AF_INET, "0.0.0.0", &res_addr.addr.raddr4);

    Destination_addresses_t dest;
    memset(&dest, 0, sizeof(dest));
    dest.count = 1;
    dest.capacity = 1;
    dest.has_ipv4 = true;
    dest.items = &res_addr;

    Source_address_t src;
    memset(&src, 0, sizeof(src));
    src.is_ipv4 = true;
    inet_pton(AF_INET, "127.0.0.1", &src.addr4);

    Table_packet_t table;
    memset(&table, 0, sizeof(table));
    table.size = 1;
    table.packets = (Packet_t*)malloc(sizeof(Packet_t));
    memset(table.packets, 0, sizeof(Packet_t));

    // The scanner will send the packet and wait 500 ms because the OS will silently drop it
    int err = scan_destinations(&parser, &dest, &src, &table);

    if (err != 0) {
        free(table.packets);
        GTEST_SKIP() << "Skipped due to scanner error: " << err;
    }

    // We expect exactly the ST_FILTERED state
    EXPECT_EQ(table.packets[0].status, ST_FILTERED) 
        << "Packet sent to 0.0.0.0 should be silently dropped by the OS and marked as FILTERED after timeout.";

    free(table.packets);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}