CC=gcc
CFLAGS=-g -Wall -Wextra

all: key_gen build_hash_blk_index blockinfo
key_gen: key_gen.c
	$(CC) $^ $(CFLAGS) -lsecp256k1 -lcrypto -o $@
build_hash_blk_index: build_hash_blk_index.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
blockinfo: blockinfo.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
clean:
	rm key_gen build_hash_blk_index blockinfo
