CC=gcc
CFLAGS=

all: key_gen block_parser
key_gen: key_gen.c
	$(CC) $^ $(CFLAGS) -lsecp256k1 -lcrypto -o $@
block_parser: block_parser.c
	$(CC) $^ $(CFLAGS) -o $@
clean:
	rm key_gen block_parser
