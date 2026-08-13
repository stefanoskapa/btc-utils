#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <time.h>

#define BLK_MAX_SIZE 134217728
#define HT_CAPACITY 8388608 
#define MINED_BLOCKS 1000000
#define PRIME_MULTIPLIER 5

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

void print_hex_nolf(unsigned char *array, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
}
void print_hex(unsigned char *array, size_t len) {
    print_hex_nolf(array, len);
    puts("");
}

uint32_t ht_hash(const unsigned char *array) {
    uint32_t result; 
    memcpy(&result, array, 4);
    return result >> 10;
}

void show_local_time(time_t epoch) {
    struct tm *local = localtime(&epoch);
    printf("%d-%d-%d %d:%d:%d", local->tm_year + 1900, local->tm_mon + 1, local->tm_mday, local->tm_hour, local-> tm_min, local->tm_sec);
}
int ht_get(unsigned char *hash) {
    int index = ht_hash(hash);
    index &= 0b00000000001111111111111111111000;
    for (int i = 0; i < 20; i++) {
        if (hash_table[index + i].is_present == false) {
            return -1;
        }
        if (memcmp(hash, hash_table[index + i].current_hash, 32) == 0) {
            return (index + i);
        }
    }
    return -1;
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
    fclose(file);
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
        return false;
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


void get_block_hash(int offset) {
    SHA256(blk_file + offset + 8, 80, sha);
    SHA256(sha, 32, sha);
}

void decrypt_blk_file() {
    int ch;
    int idx = 0;
    for (size_t i = 0; i < blk_file_size; i++) {
        ch = blk_file[i] ^ key[idx];
        blk_file[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}


void show_block(unsigned char *block_hash, int blk_num, bool hexdump) {
    int block_count = -1;

        construct_blk_path(blk_num);
        load_blk_file(blk_file_path);
        decrypt_blk_file();

        int block_offset = 0;

        while (is_magic(block_offset)) {
            block_count++;
            int *block_size;
            block_size = (int*)(blk_file + block_offset + 4);
            get_block_hash(block_offset);
            if (memcmp(block_hash, sha, 32) == 0) {
                    printf("\n");
                    printf("BLOCK ");
                    print_hex(block_hash, 32);
                    printf("==================\n");
                    printf("Meta info\n");
                    printf("---------\n");
                    printf("Offset: %d\n", block_offset);
                    printf("BLK file: %s\n", blk_file_path);
                    printf("Block size: %d bytes\n", *block_size);   
                    printf("Block header\n");
                    printf("-------------\n");
                    int *version = (int *)(blk_file + block_offset + 8);
                    printf("Version: %d\n", *version);
                    printf("Previous Block hash: ");
                    print_hex_reversed(blk_file + block_offset + 8 + 4, 32);
                    printf("Merkle Root: ");
                    print_hex_reversed(blk_file + block_offset + 8 + 4 + 32, 32);
                    int *epoch = (int *)(blk_file + block_offset + 8 + 4 + 32 + 32);
                    time_t tm = (time_t)*epoch;
                    printf("Time: %d (", *epoch);
                    show_local_time(tm);
                    puts(")");
                    int *bits = (int *)(blk_file + block_offset + 8 + 4 + 32 + 32 + 3);
                    printf("Bits: %d\n", *bits);
                    int *nonce = (int *)(blk_file + block_offset + 8 + 4 + 32 + 32 + 8 + 4);
                    printf("Nonce: %d\n", *nonce);
                    puts("");
                    if (hexdump)
                        show_block_hex(block_offset + 8, block_offset + 8 + *block_size - 1); //skip magic and size (total 8 bytes)
                    return;
                } else {
                    block_offset += 8 + *block_size;
                }
        }

    printf("Block was not found!\n");
}

int hex_to_le32(const char *hex, unsigned char out[32]) {
    if (strlen(hex) != 64) {
        puts("hex not 64 bytes");
        return -1;
    }

    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return -1;
        out[31 - i] = (unsigned char)byte;
    }
    return 0;
}

bool file_exists(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return false;
    }
    fclose(f);
    return true;
}

void load_index() {
    FILE *f = fopen("index.dat", "rb");
    if (f == NULL){
        puts("Could not open index.dat");
        puts("Run build_hash_blk_index to create it.");
        exit(1);
    }
    fread(hash_table, sizeof(next_block), 20000000, f);
    fclose(f);
}

void string_reverse(unsigned char *str) {
    for (int i = 0; i < 16; i++) {
        str[i] = str[31 - i];
    }
}




int main(int argc, char **argv) {
    if (argc == 1) {
        printf("No block hash provided\n");
        exit(1);
    }
    int hash_arg = 1;
    bool hexdump = (argc >= 3) && (strcmp("-h", argv[1]) == 0);
    if (hexdump)
        hash_arg = 2;
    read_xor_key(xor_key_path);


    if (file_exists("index.dat")) {
        load_index();
    } else {
        printf("Could not open index.dat\n");
    }

    unsigned char block_hash_le[32];
    int res = hex_to_le32(argv[hash_arg], block_hash_le);
    if (res == -1) {
        printf("Little endian conversion error\n");
        exit(1);
    }

    int idx = ht_get(block_hash_le);
    if (idx != -1) {
        show_block(block_hash_le, hash_table[idx].blk_file_num, hexdump);
    } else {
        printf("Block not found in index!\n");
    }

    
    return EXIT_SUCCESS;
}

