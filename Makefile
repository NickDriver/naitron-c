# naitron-c build system
#
#   make            release binary  -> build/ntc
#   make test       unit tests under AddressSanitizer + UBSan
#   make coverage   llvm-cov line/function coverage report
#   make run        build + start gateway on :3000
#   make clean

# Default to clang (override with `make CC=gcc`); don't inherit make's `cc`.
ifeq ($(origin CC),default)
CC := clang
endif
STD     := -std=c23
WARN    := -Wall -Wextra -Werror
INC     := -Iinclude
COMMON  := $(STD) $(WARN) $(INC)

REL_FLAGS  := -O2 -DNDEBUG
TEST_FLAGS := -O1 -g -DUNIT_TEST -fsanitize=address,undefined -fno-omit-frame-pointer
COV_FLAGS  := -O0 -g -DUNIT_TEST -fprofile-instr-generate -fcoverage-mapping

# libcommon + core gateway (everything except the CLI main)
SRC_LIB   := $(wildcard src/common/*.c) src/core/server.c
SRC_MAIN  := src/core/main.c
SRC_TEST  := src/test/test_main.c
TESTS_INT := $(wildcard tests/*.c)   # integration tests (test build only)

# how the test binary is invoked
TEST_RUN := UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

BUILD   := build
BIN     := $(BUILD)/ntc
TESTBIN := $(BUILD)/ntc_test
COVBIN  := $(BUILD)/ntc_cov

.PHONY: all test test-unit test-it test-list coverage run clean

all: $(BIN)

$(BIN): $(SRC_LIB) $(SRC_MAIN) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) $(SRC_LIB) $(SRC_MAIN) -o $@
	@echo "built $@"

# All objects are linked directly (no static archive) so the TEST()
# constructors are never dropped by the linker.
$(TESTBIN): $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) | $(BUILD)
	$(CC) $(COMMON) $(TEST_FLAGS) $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) -o $@

test: $(TESTBIN)
	$(TEST_RUN) ./$(TESTBIN)

test-unit: $(TESTBIN)
	$(TEST_RUN) ./$(TESTBIN) unit

test-it: $(TESTBIN)
	$(TEST_RUN) ./$(TESTBIN) it

test-list: $(TESTBIN)
	./$(TESTBIN) list

coverage: | $(BUILD)
	$(CC) $(COMMON) $(COV_FLAGS) $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) -o $(COVBIN)
	LLVM_PROFILE_FILE=$(BUILD)/ntc.profraw ./$(COVBIN) >/dev/null 2>&1 || true
	xcrun llvm-profdata merge -sparse $(BUILD)/ntc.profraw -o $(BUILD)/ntc.profdata
	xcrun llvm-cov report ./$(COVBIN) -instr-profile=$(BUILD)/ntc.profdata $(SRC_LIB)

run: $(BIN)
	./$(BIN) start 3000

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
