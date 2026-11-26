# Host tests: the library against the shared signing vectors, with OpenSSL
# standing in for the device's hashes.
CC ?= cc
CFLAGS ?= -std=c99 -Wall -Wextra -Werror -pedantic -O2
VECTORS ?= ../fixtures/signing/composite.txt

build/vectors: src/sign.c src/update.c src/tz_json.c src/tz_json.h port/hash_openssl.c test/vectors.c include/tenzro/sign.h include/tenzro/update.h port/tz_hash.h
	mkdir -p build
	$(CC) $(CFLAGS) -Iinclude -Iport -Isrc src/sign.c src/update.c src/tz_json.c port/hash_openssl.c test/vectors.c -lcrypto -o $@

test: build/vectors
	./build/vectors $(VECTORS)

clean:
	rm -rf build

.PHONY: test clean
