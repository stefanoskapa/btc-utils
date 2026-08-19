#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include "properties.h"
#define BLK_MAX_SIZE 134217728
const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char xor_key[8];
unsigned char blk_file[BLK_MAX_SIZE]; //128 MiB
size_t blk_file_size = 0;
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];

typedef struct block_blk_file {
    bool is_present;
    int blk_file_num;
    int blk_offset;
    unsigned char current_hash[32];
} next_block;


next_block hash_table[20000000] = {0};


uint32_t ht_hash(const unsigned char *array) {
    uint32_t result; 
    memcpy(&result, array, 4);
    return result >> 10;
}

void save_index() {
    FILE *file = fopen(HASH_IDX_FILE, "wb");
    if (file == NULL) {
        perror(NULL);
        exit(1);
    }
    size_t wrote = fwrite(hash_table, sizeof(next_block), 20000000, file);
    if (wrote != 20000000) {
        fprintf(stderr, "short write: %zu of 20000000\n", wrote);
        fclose(file);
        exit(1);
    }
    if(fclose(file) != 0) {
        perror(NULL);
        exit(1);
    }
}

bool ht_is_slot_free(int index) {
    return !(hash_table[index].is_present);
}

void ht_add(unsigned char *array, int blk_file_num, int blk_offset) {
    uint32_t index = ht_hash(array);
    index &= 0b00000000001111111111111111111000;
    int slot = 0;
    while (slot < 19 && !ht_is_slot_free(index + slot)) {
           slot++;  // find a free slot
    }
    if (slot >= 19) {
        printf("slots full!\n");
        exit(1);
    } else if (slot >= 11){
        printf("slot %d reached!\n", slot);
    }
    
    hash_table[index + slot].blk_file_num = blk_file_num;
    hash_table[index + slot].is_present = true;
    hash_table[index + slot].blk_offset = blk_offset;
    for (int i = 0; i < 32; i++) {
        hash_table[index + slot].current_hash[i] = array[i];
    }
}

void construct_blk_path(int blk_file_num) {
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
}

bool is_magic(unsigned char *array) {
    return memcmp(mainnet_magic, array, 4) == 0;
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
        xor_key[i] = ch;
    }
    fclose(key_file);
}


void get_block_hash(unsigned char *array) {
    SHA256(array, 80, sha);
    SHA256(sha, 32, sha);
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

void index_blocks(int blk_file_num) {
    printf("indexing blk%d05\n", blk_file_num);
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
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
            get_block_hash(buffer + 8);
            ht_add(sha, blk_file_num, offset); 
            offset += block_size + 8;
            fseek(block_file, block_size - 88 + 8, SEEK_CUR);
        } else {
            break;
        }

    } while(true);
    fclose(block_file);
}


bool file_exists(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

int main(void) {
        read_xor_key(xor_key_path);

        int blk_file_num = 0;
        do {

            snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
            if(!file_exists(blk_file_path)) {
                    break;
            }
            index_blocks(blk_file_num);
            blk_file_num++;
        } while(true);
        printf("done!\n");
        save_index();

    return EXIT_SUCCESS;
}

