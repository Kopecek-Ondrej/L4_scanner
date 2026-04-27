CC := gcc
CXX := g++

SRC_DIR := src
TEST_DIR := tests
BUILD_DIR := build

CPPFLAGS := -I$(SRC_DIR) -MMD -MP -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L
TEST_CPPFLAGS := $(CPPFLAGS) -I$(TEST_DIR)

CFLAGS := -pedantic -Werror -Wall -Wextra -pthread -std=c17
CXXFLAGS := -Wall -Wextra -pthread -std=c++20

# libraries
LDLIBS := -lnet -lpcap -pthread
TEST_LDLIBS := -lgtest -lgtest_main -lnet -lpcap -pthread

# build modes
ifeq ($(DEBUG),1)
  CFLAGS += -g3 -O0
  CXXFLAGS += -g3 -O0
  CPPFLAGS += -DDEBUG
  TEST_CPPFLAGS += -DDEBUG 
else
  CFLAGS += -O2
  CXXFLAGS += -O2
endif

SRCS := $(wildcard $(SRC_DIR)/*.c)
APP_SRC := $(SRC_DIR)/ipk-L4-scan.c
LIB_SRCS := $(filter-out $(APP_SRC), $(SRCS))

OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

TARGET := ipk-L4-scan

# --- tests ---
TEST_CPP_SRCS := $(wildcard $(TEST_DIR)/*.cpp)
TEST_CPP_OBJS := $(TEST_CPP_SRCS:$(TEST_DIR)/%.cpp=$(BUILD_DIR)/$(TEST_DIR)/%.o)

TEST_LIB_OBJS := $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.test.o)

TEST_CPP_DEPS := $(TEST_CPP_OBJS:.o=.d)
TEST_LIB_DEPS := $(TEST_LIB_OBJS:.o=.d)

TEST_BIN := $(BUILD_DIR)/$(TEST_DIR)/run_tests

.DEFAULT_GOAL := all

.PHONY: all clean test run_test unit_test integration_test loopback_test cap_tests cap_app dirs

#as say the instructions
NixDevShellName: 
	@echo "c"
all: dirs $(TARGET)

test: dirs $(TEST_BIN)
	sudo ./$(TEST_BIN)

unit_test: $(TEST_BIN)
	./$(TEST_BIN) --gtest_filter=-ScannerLoopbackTest.*

integration_test: $(TEST_BIN)
	sudo ./$(TEST_BIN) --gtest_filter=ScannerLoopbackTest.*

loopback_test: integration_test

cap_tests: $(TEST_BIN)
	sudo setcap cap_net_raw,cap_net_admin=eip $(TEST_BIN)

cap_app: $(TARGET)
	sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET)

dirs:
	@mkdir -p $(BUILD_DIR) $(BUILD_DIR)/$(TEST_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/%.test.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(BUILD_DIR)/$(TEST_DIR)/%.o: $(TEST_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(TEST_CPPFLAGS) -c $< -o $@

$(TEST_BIN): $(TEST_CPP_OBJS) $(TEST_LIB_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(TEST_LDLIBS)

run_test: $(TEST_BIN)
	./$(TEST_BIN)

clean:
	@rm -rf $(BUILD_DIR) $(TARGET)

# Auto-generated dependency files
-include $(DEPS) $(TEST_CPP_DEPS) $(TEST_LIB_DEPS)