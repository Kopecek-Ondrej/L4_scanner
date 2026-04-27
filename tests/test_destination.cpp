#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>

extern "C" {
    #include "cli_parser.h"
    #include "error_code.h"
    #include "destination.h"
}

TEST(DestinationResolveTargetTest, RejectsUnknownHostname) {
    Cli_Parser_t parser{};
    Source_address_t source{};
    Destination_addresses_t destination{};

    parser.hostname = (char*)"nonexistent-hostname-for-ipk-tests.invalid";
    source.is_ipv4 = true;
    source.is_ipv6 = true;

    int rc = resolve_target(&parser, &destination, &source);

    EXPECT_EQ(rc, ERR_RESOLVE_HOST);
    free_destination_addresses(&destination);
}

TEST(DestinationResolveTargetTest, RejectsWhenNoLocalAddressFamilyIsAvailable) {
    Cli_Parser_t parser{};
    Source_address_t source{};
    Destination_addresses_t destination{};

    parser.hostname = (char*)"localhost";
    source.is_ipv4 = false;
    source.is_ipv6 = false;
    source.is_local_ipv6 = false;

    int rc = resolve_target(&parser, &destination, &source);

    EXPECT_EQ(rc, ERR_RESOLVE_HOST);
    EXPECT_EQ(destination.count, 0u);
    free_destination_addresses(&destination);
}

TEST(DestinationResolveTargetTest, ResolvesLocalhostUsingIPv4WhenIPv4Available) {
    Cli_Parser_t parser{};
    Source_address_t source{};
    Destination_addresses_t destination{};

    parser.hostname = (char*)"localhost";
    source.is_ipv4 = true;
    source.is_ipv6 = false;
    source.is_local_ipv6 = false;

    int rc = resolve_target(&parser, &destination, &source);

    EXPECT_EQ(rc, EXIT_OK);
    EXPECT_GT(destination.count, 0u);
    EXPECT_TRUE(destination.has_ipv4);

    bool contains_ipv4 = false;
    for(size_t i = 0; i < destination.count; ++i) {
        if(destination.items[i].family == AF_INET) {
            contains_ipv4 = true;
            break;
        }
    }

    EXPECT_TRUE(contains_ipv4);
    free_destination_addresses(&destination);
}