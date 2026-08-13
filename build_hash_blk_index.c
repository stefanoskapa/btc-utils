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
unsigned char key[8];
unsigned char blk_file[BLK_MAX_SIZE]; //128 MiB
size_t blk_file_size = 0;
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];

typedef struct block_blk_file {
    bool is_present;
    int blk_file_num;
    unsigned char current_hash[32];
} next_block;


next_block hash_table[20000000] = {0};


uint32_t ht_hash(const unsigned char *array) {
    uint32_t result; 
    memcpy(&result, array, 4);
    return result >> 10;
}

void save_index() {
    FILE *file = fopen("index.dat", "wb");
    if (file == NULL) {
        perror("fopen index.dat");
        exit(1);
    }
    size_t wrote = fwrite(hash_table, sizeof(next_block), 20000000, file);
    if (wrote != 20000000) {
        fprintf(stderr, "short write: %zu of 20000000\n", wrote);
        fclose(file);
        exit(1);
    }
    if(fclose(file) != 0) {
        perror("fclose index.dat");
        exit(1);
    }
}

bool ht_is_slot_free(int index) {
    return !(hash_table[index].is_present);
}

void ht_add(unsigned char *array, int blk_file_num) {
    uint32_t index = ht_hash(array);
    index &= 0b00000000001111111111111111111000;
    int slot = 0;
    while (slot < 19 && !ht_is_slot_free(index + slot)) {
           slot++;  // find a free slot
    }
    if (slot >= 19) {
        printf("slots full!\n");
        exit(1);
    } else if (slot >= 15){
        printf("slot %d reached!\n", slot);
    }
    
    hash_table[index + slot].blk_file_num = blk_file_num;
    hash_table[index + slot].is_present = true;
    for (int i = 0; i < 32; i++) {
        hash_table[index + slot].current_hash[i] = array[i];
    }
}

void construct_blk_path(int blk_file_num) {
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
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
    FILE *block_file = fopen(path, "rb");
    if (block_file == NULL) {
        return false;
    }
    blk_file_size = fread(blk_file, 1, BLK_MAX_SIZE, block_file);
    fclose(block_file);
    return true;
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


void get_block_hash(int offset) {
    SHA256(blk_file + offset + 8, 80, sha);
    SHA256(sha, 32, sha);
}

void decrypt_header(size_t pos) {
    size_t idx = pos % 8;
    int ch;
    for (size_t i = pos; i < pos + 8 + 80; i++) {
        ch = blk_file[i] ^ key[idx];
        blk_file[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}

void index_blocks() {

    printf("indexing...\n");
    for (int y = 0; y <= 99999; y++) {

        construct_blk_path(y);
        if(!load_blk_file(blk_file_path)) {
            return;
        }
        int block_offset = 0;
        int *block_size; 
        int blk_block_count = 0;
        decrypt_header(block_offset);
        while (is_magic(block_offset)) {
            blk_block_count++;
            block_size = (int*)(blk_file + block_offset + 4);
            get_block_hash(block_offset);
            ht_add(sha, y);
            block_offset += 8 + *block_size; // will jump straight to the next block header
            decrypt_header(block_offset);
        }
        printf("%s loaded! (%d blocks found)\n", blk_file_path, blk_block_count);
    }

    printf("indexing complete!\n");
}

bool file_exists(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

int main(int argc, char **argv) {
    read_xor_key(xor_key_path);
    bool overwrite = argc > 1 && strcmp("-f", argv[1]) == 0;
    if (file_exists("index.dat") && !overwrite) {
        printf("index.dat already exists! Use -f to override");
        exit(EXIT_FAILURE);
    } else {
        index_blocks();
        save_index();
    }

    return EXIT_SUCCESS;
}

