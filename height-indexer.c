#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <time.h>

#define LOOK_BACK 200

const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_folder = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char xor_key[8];
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];
unsigned char current_hash[SHA256_DIGEST_LENGTH];
FILE *order;
typedef struct header {
    unsigned char block_header[80];
} header;
header headers[2000000] = {0};
size_t header_count = 0;
size_t indexed_blocks = 1;
unsigned char genesis[32] = {
    0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72,
    0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7, 0x4f,
    0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c,
    0x68, 0xd6, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00
};

void append_hash(unsigned char *hash) {
    if (order == NULL) {
        perror(NULL);
        exit(1);
    }
    for (int i = 31; i >= 0; i--) {
        fprintf(order, "%02x", hash[i]);
    }
    fprintf(order, "\n");
}

void print_hex_nolf(unsigned char *array, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
}
void print_hex(unsigned char *array, size_t len) {
    print_hex_nolf(array, len);
    puts("");
}

void print_hex_reversed_nolf(unsigned char *array, size_t len) {
    for (int i = len -1; i >= 0; i--) {
        printf("%02x", array[i]);
    }
}

void print_hex_reversed(unsigned char *array, size_t len) {
    print_hex_reversed_nolf(array, len);
    puts("");
}


bool is_magic(unsigned char *array) {
    return memcmp(mainnet_magic, array, 4) == 0;
}

void decrypt(unsigned char *array, size_t size, size_t offset) {
    int ch;
    int idx = offset % 8;
    for (size_t i = 0; i < size ; i++) {
        ch = array[i] ^ xor_key[idx];
        array[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}

void read_xor_key(const char *path) {
    FILE *key_file = fopen(path,"rb");
    if (key_file == NULL) {
        perror(NULL);
        exit (1);
    }
    for (int i = 0; i < 8; i++) {
        unsigned char ch = fgetc(key_file);
        xor_key[i] = ch;
    }
    fclose(key_file);
}

void get_block_hash(size_t index) {
    SHA256(headers[index].block_header, 80, sha);
    SHA256(sha, 32, sha);
}

bool file_exists(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

void load_blk_headers() {
    size_t offset = 0;
    static unsigned char buffer[88] = {0}; 
    FILE *block_file = fopen(blk_file_path, "rb");
    if (block_file == NULL) {
        perror(NULL);
        exit(1);
    }
    int blocks_found = 0; 
    do {
        int elements_read = fread(buffer, sizeof(buffer), 1, block_file);
        if (elements_read != 1) {
            break;
        }
        decrypt(buffer, 88, offset);
        if (is_magic(buffer)) {
            uint32_t block_size;
            memcpy(&block_size, buffer + 4, 4);
            blocks_found++;
            memcpy(headers + header_count, buffer + 8, 80);
            header_count++;
            offset += block_size + 8;
            fseek(block_file, block_size - 88 + 8, SEEK_CUR);
        } else {
            //printf("Critical error, Magic not found\n");
            break;
        }

    } while(true);
    //printf("%s (headers:%d)\n ", blk_file_path, blocks_found);
    fclose(block_file);
}

bool find_next_hash(unsigned char *hash) {
    size_t start = 0;
    if (indexed_blocks > LOOK_BACK) {
        start = indexed_blocks - LOOK_BACK;
    }
    for (size_t i = start; i < header_count; i++) {
        if (memcmp(hash, headers[i].block_header + 4, 32)  == 0) {
            get_block_hash(i);
            return true;
        }
    }
    return false;
}

int main(void) {
    read_xor_key(xor_key_path);

    fprintf(stdout,"Loading block headers...");
    fflush(stdout);
    int blk_num = 0;
    do {
        snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_folder, blk_num);
        if (!file_exists(blk_file_path)) {
            break;
        }
        load_blk_headers();
        blk_num++;
    } while (true);
    puts("done");

    printf("Loaded %lu headers\n", header_count);

    fprintf(stdout,"Indexing blocks...");
    fflush(stdout);
    order = fopen("block-order.txt", "w");
    append_hash(genesis);

    unsigned char current_hash[32] = {0};
    memcpy(current_hash,genesis, 32);

    while (find_next_hash(current_hash)) {
        append_hash(sha);
        memcpy(current_hash,sha, 32);
        indexed_blocks++;
    }
    puts("done");
    printf("%lu blocks have been indexed\n", indexed_blocks);

    fclose(order);
    return EXIT_SUCCESS;
}

