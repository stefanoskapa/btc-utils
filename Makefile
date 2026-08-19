CC=gcc
CFLAGS=-g -Wall -Wextra
BUILD_DIR=build/
all: key_gen hash-indexer blockinfo P2PK-extract height-indexer
key_gen: key_gen.c
	$(CC) $^ $(CFLAGS) -lsecp256k1 -lcrypto -o $(BUILD_DIR)$@
hash-indexer: hash-indexer.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $(BUILD_DIR)$@
blockinfo: blockinfo.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $(BUILD_DIR)$@
P2PK-extract: P2PK-extract.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $(BUILD_DIR)$@
height-indexer: height-indexer.c
	$(CC) $^ $(CFLAGS) -lcrypto -o $(BUILD_DIR)$@
clean:
	rm $(BUILD_DIR)*
