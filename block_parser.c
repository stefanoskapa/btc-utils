#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>

#define BLK_MAX_SIZE 134217728
const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
//const int BLK_MAX_SIZE = 134217728;
unsigned char key[8];
unsigned char blk_file[BLK_MAX_SIZE]; //128 MiB
size_t blk_file_size = 0;
char blk_file_path[512];

void construct_blk_path(int blk_file_num) {
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
    //printf("path constructed: %s\n", blk_file_path);
}

void print_hex(unsigned char *array, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
    puts("");
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
    printf("Loading %s...\n", path);
    FILE *block_file = fopen(path, "rb");
    if (block_file == NULL) {
        return false;
    }
    int ch;
    size_t idx = 0;
    size_t counter = 0;

    blk_file_size = fread(blk_file, 1, BLK_MAX_SIZE, block_file);
    fclose(block_file);
    
    // decrypt file in memory
    for (int i = 0; i < blk_file_size; i++) {
        ch = blk_file[i]; 
        unsigned char byte = ch & 0x000000FF;
        byte = (byte ^ key[idx]);
        blk_file[i] = byte;
        if (idx == 7) idx = 0; else idx++;
    }

    return true;
}

void print_safe_ch(unsigned char ch) {
    if (ch < ' ' || ch > '~') {
        printf(".");
    } else {
        printf("%c", ch);
    }
}

void show_block_hex(size_t start, size_t end) {

    for (size_t i = start; i <= end; i += 16) {
        int j;
        for (j = 0; j < 16; j++) { // show hex
            if (i + j > end) {
                break;
            }
            printf("%02x ", blk_file[i + j]);
            if (j == 7) printf(" ");
        }
        if (end - start - i < 16) { //we are on the last line, fill with spaces
            int num_spaces = 16 * 3 + 1;
            num_spaces -= j * 3;
            if (j > 7) num_spaces--;
            for (int j = 0; j < num_spaces; j++) {
                printf(" ");
            }
        }
        printf(" ");
        for (j = 0; j < 16; j++) { // attempt to print characters
            if (i + j > end) {
                puts("");
                return;
            }

            print_safe_ch(blk_file[i + j]);
        }
        puts("");

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


void show_nth_block(int block_num) {
    int block_count = -1;
    for (int y = 0; y <= 99999; y++) {

        construct_blk_path(y);
        load_blk_file(blk_file_path);

        int block_offset = 0;

        while (is_magic(block_offset)) {
            block_count++;
            int *block_size;
            block_size = (int*)(blk_file + block_offset + 4);
                if (block_count == block_num) {
                    printf("\n");
                    printf("BLOCK %d\n", block_num);
                    printf("==================\n");
                    printf("Offset: %d\n", block_offset);
                    printf("BLK file: %s\n", blk_file_path);
                    printf("Block size: %d bytes\n", *block_size);   
                    unsigned char sha[SHA256_DIGEST_LENGTH];
                    SHA256(blk_file + block_offset + 8, 80, sha);
                    SHA256(sha, 32, sha);
                    printf("Current Block hash:  ");
                    print_hex_reversed(sha, 32);
                    printf("Previous Block hash: ");
                    print_hex_reversed(blk_file + block_offset + 8 + 4, 32);
                    show_block_hex(block_offset + 8, block_offset + 8 + *block_size - 1); //skip magic and size (total 8 bytes)
                    return;
                } else {
                    block_offset += 8 + *block_size;
                }
        }

    }
    printf("Block %d was not found!\n", block_num);
}

void fail_parse_int() {
    fprintf(stderr, "Not a valid positive 32-bit integer\n");
    exit(EXIT_FAILURE);
}

int32_t parse_int_positive(char *str) {
    uint64_t result = 0;
    size_t str_size = strlen(str);

    if (str_size > 10) fail_parse_int();

    for (int i = 0; i < str_size; i++) {
        unsigned char ch = str[i];
        if (ch < '0' || ch > '9') {
            fail_parse_int();
        }
        int digit = ch - '0';
        int multiplier = 1;
        for (int j = 0; j < str_size - (i + 1); j++) {
            multiplier *= 10; 
        }
        result += (digit * multiplier); 
    }
    if (result > INT_MAX) fail_parse_int();

    return (int32_t) result;

}

int main(int argc, char **argv) {
    if (argc == 1) {
        printf("No block number provided\n");
        exit(1);
    }
    int block_num = parse_int_positive(argv[1]);
    printf("Looking for block %d...\n", block_num);
    read_xor_key(xor_key_path);

    show_nth_block(block_num);

    return EXIT_SUCCESS;
}

