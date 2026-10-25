CC         ?= cc
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl)
UDEV_CFLAGS    := $(shell pkg-config --cflags libudev)
UDEV_LIBS      := $(shell pkg-config --libs libudev)
# Phase 4 onward: usb_lockdown.c needs libudev, which only exists on Linux
# (the deployment target). Build and test this binary inside
# scripts/test-vm-setup.sh's container, not on a macOS/BSD host.
CFLAGS  += -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D_DARWIN_C_SOURCE \
           -Wall -Wextra -Werror -g -pthread -I../proto -Isrc -I../third_party/cJSON \
           $(OPENSSL_CFLAGS) $(UDEV_CFLAGS)
LDFLAGS += -pthread $(OPENSSL_LIBS) $(UDEV_LIBS)

SRC_LOCAL := $(shell find src -name '*.c')
OBJ_LOCAL := $(SRC_LOCAL:.c=.o)
CJSON_OBJ := build/cJSON.o
BIN       := bin/mdm-agent

.PHONY: all clean

all: $(BIN)

$(BIN): $(OBJ_LOCAL) $(CJSON_OBJ)
	@mkdir -p bin
	$(CC) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

build/cJSON.o: ../third_party/cJSON/cJSON.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ_LOCAL)
	rm -rf build bin
