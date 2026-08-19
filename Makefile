CC=gcc
CFLAGS=-g -Wall -Wextra

all: key_gen indexer blockinfo P2PK-extract height-indexer
key_gen: key_gen.c
	$(CC) $^ $(CFLAGS) -lsecp256k1 -lcrypto -o $@
indexer: indexer.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
blockinfo: blockinfo.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
P2PK-extract: P2PK-extract.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
height-indexer: height-indexer.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $@
clean:
	rm key_gen indexer blockinfo P2PK-extract height-indexer
