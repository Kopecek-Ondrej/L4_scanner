CC := gcc
CFLAGS := -g -pedantic -Werror -Wall -Wextra
SRC_DIR := src
BUILD_DIR := build
CPPFLAGS := -I$(SRC_DIR)
TEST_CPPFLAGS := $(CPPFLAGS) -DTEST_BUILD
# Enable HOME_TEST=1 to include home-only interface test in test_main
ifeq ($(HOME_TEST),1)
TEST_CPPFLAGS += -DHOME_TEST
endif

ifeq ($(DEBUG),1)
CPPFLAGS += -DDEBUG
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
APP_SRC := $(SRC_DIR)/ipk-L4-scan.c
LIB_SRCS := $(filter-out $(APP_SRC), $(SRCS))
HEADERS := $(wildcard $(SRC_DIR)/*.h)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

TARGET := $(BUILD_DIR)/ipk-L4-scan

TEST_SRCS := tests/test_main.c tests/test_cli.c tests/test_interface.c tests/helper.c
TEST_OBJS := $(TEST_SRCS:tests/%.c=$(BUILD_DIR)/tests/%.o)
TEST_BIN := $(BUILD_DIR)/tests/test_main
TEST_LIB_OBJS := $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.test.o)

.PHONY: all clean test run_test dirs

all: dirs $(TARGET)

test: dirs $(TEST_BIN)

dirs:
	@mkdir -p $(BUILD_DIR) $(BUILD_DIR)/tests

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.test.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/tests/%.o: tests/%.c $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(TEST_OBJS) $(TEST_LIB_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

run_test: $(TEST_BIN)
	./$(TEST_BIN)
	@rm -f $(OBJS) $(TARGET) $(TEST_OBJS) $(TEST_BIN) $(TEST_LIB_OBJS)

clean:
	@rm -f $(OBJS) $(TARGET) $(TEST_OBJS) $(TEST_BIN) $(TEST_LIB_OBJS)