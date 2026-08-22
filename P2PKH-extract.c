#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <time.h>
#include "opcodes.h"

#define BLK_MAX_SIZE 134217728


const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char key[8];
unsigned char blk_file[BLK_MAX_SIZE];
size_t blk_file_size = 0;
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];

uint64_t duplicates = 0;

FILE *results;

void print_hex_nolf(unsigned char *array, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
}
void print_hex(unsigned char *array, size_t len) {
    print_hex_nolf(array, len);
    puts("");
}

void add_key20(size_t offset) {
    //for (int i = 19; i >= 0; i--) {
    for (int i = 0; i < 20; i++) {
        fprintf(results, "%02x", blk_file[offset + i]);
    }
    fprintf(results, "\n");
}

uint32_t ht_hash(const unsigned char *array) {
    uint32_t result; 
    memcpy(&result, array, 4);
    return result >> 10;
}

uint64_t parse_compact_size(int *offset) {
    unsigned char size = blk_file[*offset];
    if (size <= 0xFC) {
        *offset += 1;
        return size;
    } else if (size == 0xFD) {
        unsigned short *res = (unsigned short *)(blk_file + *offset + 1);
        *offset += 3;
        return *res;
    } else if (size == 0xFE) {
        unsigned int *res = (unsigned int *)(blk_file + *offset + 1);
        *offset += 5;
        return *res;
    } else { //0xFF
        unsigned long *res = (unsigned long *)(blk_file + *offset + 1);
        *offset += 9;
        return *res;
    } 
}

void construct_blk_path(int blk_file_num) {
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
}

void print_hex_reversed(unsigned char *array, size_t len) {
    for (int i = len -1; i >= 0; i--) {
        printf("%02x", array[i]);
    }
    puts("");
}

bool is_magic(size_t index) {
    if (index >= blk_file_size) 
        return false;
    for (int i = 0; i < 4; i++) {
        if (blk_file[index + i] != mainnet_magic[i]) {
            return false;
        }
    }
    return true;
}

bool load_blk_file(char *path) {
    //printf("Loading %s...\n", path);
    FILE *block_file = fopen(path, "rb");
    if (block_file == NULL) {
        printf("Could not open %s.\n", path);
        exit(0);
    }
    blk_file_size = fread(blk_file, 1, BLK_MAX_SIZE, block_file);
    fclose(block_file);
    return true;
}

void print_safe_ch(unsigned char ch) {
    if (ch < ' ' || ch > '~') {
        printf(".");
    } else {
        printf("%c", ch);
    }
}

void read_xor_key(const char *path) {
    FILE *key_file = fopen(path,"rb");
    if (key_file == NULL) {
        printf("failed to open xor file\n");
        exit (1);
    }
    for (int i = 0; i < 8; i++) {
        unsigned char ch = fgetc(key_file);
        key[i] = ch;
    }
    fclose(key_file);
}
void decrypt_blk_file(void) {
    uint64_t k;
    memcpy(&k, key, 8);
    size_t n = blk_file_size / 8;
    uint64_t *p = (uint64_t *)blk_file;
    for (size_t i = 0; i < n; i++) p[i] ^= k;
    // handle the tail (blk_file_size % 8) byte-by-byte
    for (size_t i = n * 8; i < blk_file_size; i++)
        blk_file[i] ^= key[i & 7];
}

void collect_keys() {

    for (int blk_num = 0; blk_num < 99999; blk_num++) {
        size_t blk_offset = 0;
        construct_blk_path(blk_num);
        load_blk_file(blk_file_path);
        printf("looking in %s...", blk_file_path);
        decrypt_blk_file();

        int block_offset = 0;

        size_t key_count = 0;
        while(is_magic(block_offset)) {
            int *block_size;
            block_size = (int*)(blk_file + block_offset + 4);
            int offset = block_offset;
            
            // Go to transactions
            // (magic(4) + size(4) + version(4) + prev(32) + merkle(32) + time(4) + bits(4) + nonce(4)
            offset += 88;

            size_t tx_count = parse_compact_size(&offset);
            for (size_t cur_tx = 0; cur_tx < tx_count; cur_tx++) {

                bool is_segwit = false;
                offset += 4;

                unsigned char *marker = (unsigned char *)(blk_file + offset);
                if (*marker == 0) {
                    unsigned char *flag = (unsigned char *)(blk_file + offset + 1);
                    offset += 2;
                    is_segwit = *flag >= 1; // (*marker == 0 && *flag >= 1);
                }

                // Iterating transaction inputs
                size_t input_count = parse_compact_size(&offset);

                for (size_t i = 0; i < input_count; i++) {
                    // Go to ScriptSig size
                    // TXID(32) + VOUT(4)
                    offset +=36;

                    size_t script_size = parse_compact_size(&offset);
                    offset += script_size;

                    // Skip Sequence(4)
                    offset += 4; 
                }

                size_t output_count = parse_compact_size(&offset);

                for (size_t i = 0; i < output_count; i++) {
                    offset += 8; // Amount(8)

                    size_t scriptpubkey_size = parse_compact_size(&offset);
                    if (scriptpubkey_size == 25) {
                        if (blk_file[offset] == OP_DUP && 
                            blk_file[offset + 1] == OP_HASH160 && 
                            blk_file[offset + 1 + 1] == OP_PUSHBYTES_20 &&
                            blk_file[offset + 1 + 1 + 1 + 20] == OP_EQUALVERIFY &&
                            blk_file[offset + 1 + 1 + 1 + 20 + 1] == OP_CHECKSIG) {
                                add_key20(offset + 1 + 1 + 1);
                                key_count++; 
                            }
                    }
                    offset += scriptpubkey_size;
                }


                if (is_segwit) {
                    for (size_t in = 0; in < input_count; in++) {
                        size_t stack_items = parse_compact_size(&offset);
                        for (size_t i = 0; i < stack_items; i++) {
                            size_t stack_item_size = parse_compact_size(&offset);
                            offset += stack_item_size;
                        }
                    }
                }

                offset += 4; // Skip Locktime(4)
            }
            block_offset += 8 + *block_size; // magic(4) + size(4) + block-size

        }
        printf(" (keys: %lu)\n", key_count);
    }
}

bool file_exists(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

void string_reverse(unsigned char *str) {
    for (int i = 0; i < 16; i++) {
        str[i] = str[31 - i];
    }
}



int main(void) {

    read_xor_key(xor_key_path);

    results = fopen("hashed-keys.txt", "w");
    if (results == NULL) {
        perror(NULL);
        exit(1);
    }

    collect_keys();
    fclose(results);
    printf("DONE!\n");

    return EXIT_SUCCESS;
}

