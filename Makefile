CC=gcc
CFLAGS=-g -Wall -Wextra
BUILD_DIR=build/
LIBS=-lsecp256k1 -lcrypto 

all: key_gen height-indexer hash-indexer blockinfo P2PK-extract P2PKH-extract bip-39
%: %.c
	$(CC) $^ $(CFLAGS) $(LIBS) -o $(BUILD_DIR)$@
clean:
	rm $(BUILD_DIR)*
