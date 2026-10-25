CC      ?= cc
CFLAGS  += -std=c11 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
           -Wall -Wextra -Werror -g -I../proto -Isrc -I../third_party/cJSON
LDFLAGS +=

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
