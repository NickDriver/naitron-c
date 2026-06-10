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

# core + registry link against SQLite (the control-plane DB)
LDLIBS := -lsqlite3

# BearSSL (vendored submodule) supplies RS256 verification + TLS. Only the
# core/test/coverage binaries need it - NOT the controller or language SDKs.
BEARSSL_DIR := third_party/bearssl
BEARSSL_INC := -I$(BEARSSL_DIR)/inc
BEARSSL_LIB := $(BEARSSL_DIR)/build/libbearssl.a

# miniz (vendored single-file) supplies gzip/DEFLATE. Compiled separately with
# warnings relaxed (third-party); only core/test/cov link it.
MINIZ_DIR := third_party/miniz
MINIZ_INC := -I$(MINIZ_DIR)

# libcommon + core gateway (everything in src/core except the CLI main)
SRC_LIB   := $(wildcard src/common/*.c) \
             $(filter-out src/core/main.c, $(wildcard src/core/*.c))
SRC_MAIN  := src/core/main.c
SRC_TEST  := src/test/test_main.c
TESTS_INT := $(wildcard tests/*.c)   # integration tests (test build only)

# how the test binary is invoked
TEST_RUN := UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

BUILD   := build
BIN     := $(BUILD)/ntc
TESTBIN := $(BUILD)/ntc_test
COVBIN  := $(BUILD)/ntc_cov
MINIZ_OBJ := $(BUILD)/miniz.o

# Example out-of-process controllers (each its own binary; links the SDK + wire).
HELLO_BIN := $(BUILD)/hello_controller
SSE_BIN   := $(BUILD)/sse_controller
WS_BIN    := $(BUILD)/ws_echo
OAUTH_BIN := $(BUILD)/oauth_mock
UPLOAD_BIN:= $(BUILD)/upload_echo
SDK_SRC   := src/common/controller_sdk.c src/common/wire.c src/common/arena.c \
             src/common/slice.c src/common/http_request.c

.PHONY: all controllers test test-unit test-it test-list coverage run clean

all: $(BIN) $(HELLO_BIN) $(SSE_BIN) $(WS_BIN) $(OAUTH_BIN) $(UPLOAD_BIN)

controllers: $(HELLO_BIN) $(SSE_BIN) $(WS_BIN) $(OAUTH_BIN) $(UPLOAD_BIN)

$(BIN): $(SRC_LIB) $(SRC_MAIN) $(BEARSSL_LIB) $(MINIZ_OBJ) | $(BUILD)
	$(CC) $(COMMON) $(BEARSSL_INC) $(MINIZ_INC) $(REL_FLAGS) $(SRC_LIB) $(SRC_MAIN) $(BEARSSL_LIB) $(MINIZ_OBJ) $(LDLIBS) -o $@
	@echo "built $@"

# BearSSL static lib (submodule-internal build artifact, not tracked here).
$(BEARSSL_LIB):
	$(MAKE) -C $(BEARSSL_DIR) lib

# miniz object (third-party; warnings off so it doesn't trip -Werror).
$(MINIZ_OBJ): $(MINIZ_DIR)/miniz.c | $(BUILD)
	$(CC) $(STD) -O2 -w $(MINIZ_INC) -c $< -o $@

$(HELLO_BIN): controllers/hello_controller.c $(SDK_SRC) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) controllers/hello_controller.c $(SDK_SRC) -o $@
	@echo "built $@"

$(SSE_BIN): controllers/sse_controller.c $(SDK_SRC) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) controllers/sse_controller.c $(SDK_SRC) -o $@
	@echo "built $@"

$(WS_BIN): controllers/ws_echo.c $(SDK_SRC) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) controllers/ws_echo.c $(SDK_SRC) -o $@
	@echo "built $@"

$(OAUTH_BIN): controllers/oauth_mock.c $(SDK_SRC) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) controllers/oauth_mock.c $(SDK_SRC) -o $@
	@echo "built $@"

$(UPLOAD_BIN): controllers/upload_echo.c $(SDK_SRC) | $(BUILD)
	$(CC) $(COMMON) $(REL_FLAGS) controllers/upload_echo.c $(SDK_SRC) -o $@
	@echo "built $@"

# All objects are linked directly (no static archive) so the TEST()
# constructors are never dropped by the linker.
$(TESTBIN): $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) $(BEARSSL_LIB) $(MINIZ_OBJ) | $(BUILD)
	$(CC) $(COMMON) $(BEARSSL_INC) $(MINIZ_INC) $(TEST_FLAGS) $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) $(BEARSSL_LIB) $(MINIZ_OBJ) $(LDLIBS) -o $@

# integration tests spawn the release binaries, so build them first
test: $(TESTBIN) $(BIN) $(HELLO_BIN) $(SSE_BIN) $(WS_BIN) $(OAUTH_BIN) $(UPLOAD_BIN)
	$(TEST_RUN) ./$(TESTBIN)

test-unit: $(TESTBIN)
	$(TEST_RUN) ./$(TESTBIN) unit

test-it: $(TESTBIN) $(BIN) $(HELLO_BIN) $(SSE_BIN) $(WS_BIN) $(OAUTH_BIN) $(UPLOAD_BIN)
	$(TEST_RUN) ./$(TESTBIN) it

test-list: $(TESTBIN)
	./$(TESTBIN) list

coverage: $(BEARSSL_LIB) $(MINIZ_OBJ) | $(BUILD)
	$(CC) $(COMMON) $(BEARSSL_INC) $(MINIZ_INC) $(COV_FLAGS) $(SRC_LIB) $(TESTS_INT) $(SRC_TEST) $(BEARSSL_LIB) $(MINIZ_OBJ) $(LDLIBS) -o $(COVBIN)
	LLVM_PROFILE_FILE=$(BUILD)/ntc.profraw ./$(COVBIN) >/dev/null 2>&1 || true
	xcrun llvm-profdata merge -sparse $(BUILD)/ntc.profraw -o $(BUILD)/ntc.profdata
	xcrun llvm-cov report ./$(COVBIN) -instr-profile=$(BUILD)/ntc.profdata $(SRC_LIB)

run: $(BIN)
	./$(BIN) start 3000

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

# build the Go + Rust example controllers (Python/TS run as scripts)
.PHONY: sdk-examples
sdk-examples:
	cd sdk/go && go build -o ../../build/go_controller ./example
	cd sdk/rust && cargo build --example hello
