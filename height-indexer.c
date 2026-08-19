#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <time.h>

#define BLK_MAX_SIZE 134217728

const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char xor_key[8];
unsigned char blk_file[BLK_MAX_SIZE * 2];
size_t blk_file1_size = 0;
size_t blk_file2_size = 0;
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];
unsigned char current_hash[SHA256_DIGEST_LENGTH];
int last_blk_loaded = -1;
bool blk_loaded = false;
FILE *order;
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

void construct_blk_path(int blk_file_num) {
    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
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


bool is_magic(size_t index) {
    if (index >= blk_file1_size + blk_file2_size) 
        return false;
    for (int i = 0; i < 4; i++) {
        if (blk_file[index + i] != mainnet_magic[i]) {
            return false;
        }
    }
    return true;
}


void decrypt_blk_file(int start, int end, int key_pos) {
    int ch;
    int idx = key_pos;
    for (size_t i = start; i <= end; i++) {
        ch = blk_file[i] ^ xor_key[idx];
        blk_file[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}

bool load_blk_file(int blk_file_num) {
    bool is_loaded = (blk_file_num == last_blk_loaded);
    if (is_loaded) {
        return true;
    } else {
        printf("Opening blk files %d-%d...\n", blk_file_num, blk_file_num + 1);
    }

    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num);
    //printf("Loading %s...\n", path);
    FILE *block_file = fopen(blk_file_path, "rb");
    //printf("opening %s\n", blk_file_path);
    if (block_file == NULL) {
        return false;
    }
    blk_file1_size = fread(blk_file, 1, BLK_MAX_SIZE, block_file);
    //printf("blk file loaded from offset %d (bytes read: %d\n", offset, blk_file_size);
    fclose(block_file);
    last_blk_loaded = blk_file_num;
    //decrypt_blk_file(0, blk_file_size -1);


    snprintf(blk_file_path, sizeof(blk_file_path), "%s/blk%05d.dat", blk_path, blk_file_num+1);
    FILE *block_file2 = fopen(blk_file_path, "rb");
    //printf("opening %s\n", blk_file_path);
    if (block_file2 == NULL) {
        return false;
    }
    blk_file2_size += fread(blk_file + blk_file1_size, 1, BLK_MAX_SIZE, block_file);
    //printf("blk file loaded from offset %d (bytes read: %d\n", offset, blk_file_size);
    fclose(block_file2);
    //decrypt_blk_file(prev_size, blk_file_size - 1);

    size_t block_offset = 0;
    decrypt_blk_file(0, 87, 0); // magic(4) + size(4) + version(4) + prevHash(32)
    while(is_magic(block_offset)) {
        int *block_size;
        block_size = (int*)(blk_file + block_offset + 4);

        block_offset += 8 + *block_size; // block_size + magic(4) + size(4) = next block start

        if (block_offset >= blk_file1_size) {
            decrypt_blk_file(block_offset, block_offset + 87, (block_offset - blk_file1_size) % 8);
        } else {
            decrypt_blk_file(block_offset, block_offset + 87, block_offset % 8);
        }
    }

    return true;
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


void get_block_hash(size_t offset) {
    SHA256(blk_file + offset + 8, 80, sha);
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

int find_successor(unsigned char *block_hash) {
    static int newest_blk_num = 0;
    //printf("Searching for successor of ");
    //print_hex_reversed(block_hash, 32);
    //printf("(start: %d)...", newest_blk_num - 1);
    for (int blk_num = newest_blk_num; blk_num < 99999; blk_num++) {
        //construct_blk_path(blk_num);
        if(load_blk_file(blk_num) == false) {
            printf("All BLK files have been parsed but hash not found.\n");
            return -1;
        }
        size_t block_offset = 0;
        //int block_count = 0;
        while(is_magic(block_offset)) {
            //printf("\tblkfile: %d block %d\n",blk_num, block_count++);
            //block_count++;
            int *block_size;
            block_size = (int*)(blk_file + block_offset + 4);
            bool is_equal = memcmp(blk_file + block_offset + 12, block_hash, 32) == 0;// 12: magic(4) + size(4) + version(4)
            if (is_equal) { // 12: magic(4) + size(4) + version(4)
                get_block_hash(block_offset);
                append_hash(sha);
                //printf("\tFound in blk%05d.dat - blk%05d.dat\n", blk_num, blk_num + 1);

                if (blk_num > newest_blk_num) {
                    newest_blk_num = blk_num;
                    //printf("blk_num > newest_blk_num (%d > %d)\n", blk_num, newest_blk_num);
                }
                return 0;
            }

            block_offset += 8 + *block_size; // block_size + magic(4) + size(4) = next block start

        }
    }
    return -1;
}

void load_last_hash() {

    FILE *f = fopen("block-order.txt", "rb");
    if (f == NULL) {
        perror(NULL);
        exit(1);
    }
    fseek(f, -65, SEEK_END);
    for (int i = 31; i >= 0; i--) {
        unsigned int ch;
        fscanf(f, "%2x", &ch);
        current_hash[i] = ch;
    }
    fclose(f);
}

int main(void) {
    read_xor_key(xor_key_path);

    order = fopen("block-order.txt", "a");
    if (file_exists("block-order.txt")) {
        load_last_hash();
        printf("Resuming progress starting at hash ");
        print_hex_reversed(current_hash,32);
    } else {
        memcpy(current_hash, genesis, 32);
        append_hash(genesis);
        printf("Starting indexing at Genesis block.\n");
    }

    while(find_successor(current_hash) != -1) {
        memcpy(current_hash, sha, 32); 
    }

    fclose(order);

    printf("done!\n");
    return EXIT_SUCCESS;
}

