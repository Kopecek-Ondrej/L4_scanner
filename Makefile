CC := gcc
CFLAGS := -g -pedantic -Werror -Wall -Wextra
CPPFLAGS := -I.
TEST_CPPFLAGS := $(CPPFLAGS) -DTEST_BUILD
# Enable HOME_TEST=1 to include home-only interface test in test_main
ifeq ($(HOME_TEST),1)
TEST_CPPFLAGS += -DHOME_TEST
endif
TARGET := ipk-L4-scan
SRCS := ipk-L4-scan.c cli_parser.c cli_eval.c error_code.c interface.c
HEADERS := cli_parser.h cli_eval.h error_code.h interface.h
OBJS := $(SRCS:.c=.o)

TEST_SRCS := tests/test_main.c tests/test_cli.c tests/test_interface.c tests/helper.c
TEST_OBJS := $(TEST_SRCS:.c=.o)
TEST_BIN := tests/test_main
TEST_LIB_OBJS := cli_parser.test.o cli_eval.test.o error_code.test.o interface.test.o

.PHONY: all clean test

all: $(TARGET)

test: $(TEST_BIN)


$(TEST_BIN): $(TEST_OBJS) $(TEST_LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

%.test.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

tests/%.o: tests/%.c $(HEADERS)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

run_test: $(TEST_BIN)
	./$(TEST_BIN)
	@rm -f $(OBJS)
	@rm -f $(TARGET)
	@rm -f $(TEST_OBJS) $(TEST_BIN) $(TEST_LIB_OBJS)


clean:
	@rm -f $(OBJS)
	@rm -f $(TARGET)
	@rm -f $(TEST_OBJS) $(TEST_BIN) $(TEST_LIB_OBJS)