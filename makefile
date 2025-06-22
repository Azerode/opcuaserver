# Variables

CC = gcc
CFLAGS = -Wall -Wextra

CFLAGS_INCLUDE_DEPENDENCIES = -I$(DEPS_DIR)/open62541/include \
	                         -I$(DEPS_DIR)/open62541/build/src_generated \
		                     -I$(DEPS_DIR)/open62541/plugins/include \
		                     -I$(DEPS_DIR)/json-c/ \
		                     -I$(DEPS_DIR)/json-c/build

LDFLAGS_DEPENDENCIES = -L$(DEPS_DIR)/open62541/build/bin \
                       -L$(DEPS_DIR)/json-c/build \
                       -lopen62541 \
                       -ljson-c

# Platform-specific flags
ifeq ($(shell uname -s),Linux)
	LDFLAGS_DEPENDENCIES += -Wl,-rpath,'$$ORIGIN/lib'
else ifeq ($(shell uname -s),Darwin)
	LDFLAGS_DEPENDENCIES += -Wl,-rpath,@executable_path/lib
endif

# Build configurations
BUILD_TYPE = release
BUILD_DIR = build

# Directories
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin
DEPS_DIR = deps

# Executable name
TARGET = $(BIN_DIR)/opcuaserver

# Source and object files
SRCS = $(wildcard $(SRC_DIR)/*.c)
INCLUDE = $(wildcard $(INCLUDE_DIR)/*.h)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Test specific

# Directories
TEST_BUILD_DIR = build/test
TEST_BIN_DIR = $(TEST_BUILD_DIR)/bin
TEST_DIR = tests
TEST_FIXTURES_DIR = $(TEST_DIR)/fixtures

# Executable name for tests
TEST_TARGET = $(BIN_DIR)/test_opcuaserver

# Source files for tests
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:$(TEST_DIR)/%.c=$(TEST_BUILD_DIR)/%.o)
TEST_DEPS_OBJS = $(filter-out $(BUILD_DIR)/main.o, $(OBJS))

# CFLAGS for tests
TEST_CFLAGS = -I$(DEPS_DIR)/unity/build/src \
              -I$(INCLUDE_DIR)/tests \
              -I$(DEPS_DIR)/unity/src 
TEST_CFLAGS += $(CFLAGS_INCLUDE_DEPENDENCIES)

LDFLAGS_TEST = -L$(DEPS_DIR)/unity/build -lunity


# Default target
all: directories dependencies $(TARGET)
dependencies: open62541 json-c

# Create necessary directories
directories:
	@mkdir -p $(BUILD_DIR)/$(BUILD_TYPE)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(BIN_DIR)/lib

# Build the main target
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(CFLAGS_INCLUDE_DEPENDENCIES) -o $@ $^ $(LDFLAGS_DEPENDENCIES)

# Build object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(CFLAGS_INCLUDE_DEPENDENCIES) -c $< -o $@

test: all
test: BUILD_TYPE = test
test: VERBOSE = 1
test: CFLAGS += -g3 -O0 -DDEBUG
test: unity $(TEST_TARGET)

# Build test target
$(TEST_TARGET): $(TEST_OBJS) $(TEST_DEPS_OBJS)
	$(CC) $(CFLAGS) $(CFLAGS_INCLUDE_DEPENDENCIES) $(TEST_CFLAGS) -o $@ $^ $(LDFLAGS_TEST) $(LDFLAGS_DEPENDENCIES)

# Build test object files
$(TEST_BUILD_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) $(CFLAGS_INCLUDE_DEPENDENCIES) $(TEST_CFLAGS) -c $< -o $@ 

test-leaks: test
	@echo "Running tests with leaks ..."
	leaks --atExit --list --groupByType \
	-- $(TEST_TARGET) || \
	(echo "\nMemory leaks detected!" && exit 1)

test-valgrind: test
	@echo "Running tests with Valgrind ..."
	valgrind --leak-check=full --show-leak-kinds=all \
	--track-origins=yes --verbose \
	$(TEST_TARGET) || \
	(echo "\nMemory leaks detected!" && exit 1)

# Clean build files
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

clean-test:
	rm -rf $(TEST_BUILD_DIR)

clean-release:
	rm -rf build/release

clean-debug: 
	rm -rf build/debug

clean-dsym:
	rm -rf $(BIN_DIR)/*.dSYM

# Clean everything including dependencies
clean-all: clean-test clean-debug clean-release clean clean-dsym
	rm -rf $(DEPS_DIR)

# Clean and rebuild
rebuild: clean all

# Build open62541 dependency
open62541:
	@if [ ! -d "$(DEPS_DIR)/open62541" ]; then \
		git clone https://github.com/open62541/open62541.git $(DEPS_DIR)/open62541; \
		cd $(DEPS_DIR)/open62541 && \
		git submodule update --init --recursive && \
		git checkout tag/v1.4.12; \
		mkdir -p build && cd build; \
		cmake -DBUILD_SHARED_LIBS=ON \
			-DUA_ENABLE_ENCRYPTION=MBEDTLS \
			-DUA_ENABLE_SUBSCRIPTIONS=ON \
			-DUA_ENABLE_SUBSCRIPTIONS_EVENTS=ON \
			-DUA_NAMESPACE_ZERO=ON \
			-DCMAKE_BUILD_TYPE=RELEASE ..; \
		make -j$(nproc); \
	fi
ifeq ($(shell uname -s),Darwin)
	@cp $(DEPS_DIR)/open62541/build/bin/libopen62541*.dylib $(BIN_DIR)/lib/
else
	@cp $(DEPS_DIR)/open62541/build/bin/libopen62541*.so* $(BIN_DIR)/lib/
endif

# Build json-c dependency
json-c:
	@if [ ! -d "$(DEPS_DIR)/json-c" ]; then \
		git clone https://github.com/json-c/json-c.git $(DEPS_DIR)/json-c; \
		cd $(DEPS_DIR)/json-c && \
		git submodule update --init --recursive; \
		git checkout tag/json-c-0.18-20240915; \
		mkdir build && cd build; \
		cmake -DBUILD_SHARED_LIBS=ON \
			  -DENABLE_THREADING=ON \
			  -DCMAKE_BUILD_TYPE=RELEASE ..; \
		make -j$(nproc);\
	fi
ifeq ($(shell uname -s),Darwin)
	@cp $(DEPS_DIR)/json-c/build/libjson-c*.dylib $(BIN_DIR)/lib/
else
	@cp $(DEPS_DIR)/json-c/build/libjson-c*.so* $(BIN_DIR)/lib/
endif

# Build test units framework
unity:
	@if [ ! -d "$(DEPS_DIR)/unity" ]; then \
		git clone https://github.com/ThrowTheSwitch/Unity.git $(DEPS_DIR)/unity; \
		cd $(DEPS_DIR)/unity; \
		git submodule update --init --recursive; \
		git checkout tag/v2.5.2; \
		mkdir build && cd build; \
		cmake -DBUILD_SHARED_LIBS=ON \
              -DUNITY_EXTENSION_FIXTURE=ON \
              -DUNITY_EXTENSION_MEMORY=ON \
              -DUNITY_OUTPUT_COLOR=ON ..; \
		make -j$(nproc); \
	fi

.PHONY: all clean clean-all rebuild directories open62541 json-c unity dependencies test release debug clean-dsym test-leaks
