# host-side protocol tests
# compiles the device-independent protocol sources off-target and runs them.
# the shim dir supplies a stub <3ds.h> so the shared headers parse on a host.

CXX      ?= c++
CXXFLAGS ?= -std=gnu++11 -O2 -Wall -Wextra
ROOT     := ..
INCLUDE  := -I$(ROOT)/include -Ishim

SRC := \
	$(ROOT)/source/sha256.cpp \
	$(ROOT)/source/chacha20.cpp \
	$(ROOT)/source/smaz.cpp \
	$(ROOT)/source/pow.cpp \
	$(ROOT)/source/ringbuffer.cpp \
	$(ROOT)/source/metadata.cpp \
	protocol_test.cpp

BIN := protocol_test

.PHONY: test clean
test: $(BIN)
	./$(BIN) $(ARGS)

$(BIN): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $(SRC)

clean:
	rm -f $(BIN)
