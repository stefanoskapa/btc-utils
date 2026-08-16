CC=gcc
CFLAGS=-g -Wall -Wextra

all: key_gen indexer blockinfo
key_gen: key_gen.c
	$(CC) $^ $(CFLAGS) -lsecp256k1 -lcrypto -o $@
indexer: indexer.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
blockinfo: blockinfo.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
clean:
	rm key_gen indexer blockinfo
