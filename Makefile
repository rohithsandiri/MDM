.PHONY: all agent server test clean

all: agent server

agent:
	$(MAKE) -C agent

server:
	$(MAKE) -C server

test: test-cjson

test-cjson:
	@mkdir -p tests/build
	$(CC) -std=c11 -Wall -Wextra -Werror -g \
		-Ithird_party/cJSON \
		tests/cjson_smoke_test.c third_party/cJSON/cJSON.c \
		-o tests/build/cjson_smoke_test
	./tests/build/cjson_smoke_test

clean:
	$(MAKE) -C agent clean
	$(MAKE) -C server clean
	rm -rf tests/build
