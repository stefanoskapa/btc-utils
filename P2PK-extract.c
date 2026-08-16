#include <signal.h>
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
#define MAX_KEY_ITEMS 5000000
const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char key[8];
unsigned char blk_file[BLK_MAX_SIZE];
size_t blk_file_size = 0;
char blk_file_path[512];
unsigned char sha[SHA256_DIGEST_LENGTH];
typedef struct uncompressed_key {
    unsigned char key[65];
} key65;
typedef struct compressed_key {
    unsigned char key[33];
} key33;

uint64_t duplicates = 0;
typedef struct block_blk_file {
    bool is_present;
    int blk_file_num;
    int blk_offset;
    unsigned char current_hash[32];
} next_block;

key65 keys65_found[MAX_KEY_ITEMS];
key65 keys33_found[MAX_KEY_ITEMS];
size_t keys65_size = 0;
size_t keys33_size = 0;

next_block hash_table[20000000] = {0};

void print_hex_nolf(unsigned char *array, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
    }
}
void print_hex(unsigned char *array, size_t len) {
    print_hex_nolf(array, len);
    puts("");
}

void show_current_keys() {
    printf("\n%lu keys found\n", keys65_size);
    printf("%lu duplicates\n", duplicates);
    for (size_t i = 0; i < keys65_size; i++) {
        print_hex(keys65_found[i].key, 65);
    }
    for (size_t i = 0; i < keys33_size; i++) {
        print_hex(keys33_found[i].key, 33);
    }
}
void add_key65(size_t offset) {
    for (size_t i = 0; i < keys65_size; i++) {
        if (memcmp(blk_file + offset, keys65_found[i].key, 65) == 0) {
            duplicates++;
            return;
        }
    }
    if (keys65_size == MAX_KEY_ITEMS) {
        printf("array full\n");
        show_current_keys();
        exit(1);
    }
    memcpy(keys65_found + keys65_size, blk_file + offset, 65);
    keys65_size++;
}

void add_key33(size_t offset) {
    for (size_t i = 0; i < keys33_size; i++) {
        if (memcmp(blk_file + offset, keys33_found[i].key, 33) == 0) {
            duplicates++;
            return;
        }
    }
    if (keys33_size == MAX_KEY_ITEMS) {
        printf("array full\n");
        show_current_keys();
        exit(1);
    }
    memcpy(keys33_found + keys33_size, blk_file + offset, 33);
    keys33_size++;
}

uint32_t ht_hash(const unsigned char *array) {
    uint32_t result; 
    memcpy(&result, array, 4);
    return result >> 10;
}

uint64_t parse_compact_size(int offset) {
    unsigned char size = blk_file[offset];
    if (size <= 0xFC) {
        return size;
    } else if (size == 0xFD) {
        unsigned short *res = (unsigned short *)(blk_file + offset + 1);
        return *res;
    } else if (size == 0xFE) {
        unsigned int *res = (unsigned int *)(blk_file + offset + 1);
        return *res;
    } else { //0xFF
        unsigned long *res = (unsigned long *)(blk_file + offset + 1);
        return *res;
    } 
}
int get_compact_size_size(int offset) {
    unsigned char size = blk_file[offset];
    if (size <= 0xFC) {
        return 1;
    } else if (size == 0xFD) {
        return 3;
    } else if (size == 0xFE) {
        return 5;
    } else { //0xFF
        return 9;
    } 
}
void show_local_time(time_t epoch) {
    struct tm *local = localtime(&epoch);
    printf("%d-%02d-%02d %02d:%02d:%02d", local->tm_year + 1900, local->tm_mon + 1, local->tm_mday, local->tm_hour, local-> tm_min, local->tm_sec);
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

void hex_dump(size_t start, size_t size, char *line_prefix) {
    size_t last_byte_offset = start + size;

    for (size_t i = start; i < last_byte_offset; i += 16) {
        printf("%s", line_prefix);
        for (size_t j = 0; j < 16; j ++) { 
            if (j >= size - (i - start) ) {
                printf("   ");
            } else {
                printf("%02x ", blk_file[i + j]);
            }
        }
        printf(" "); //insert an extra space between hex numbers and character representation
        for (size_t j = 0; j < 16; j++) { 
            if (i + j >= start + size) {
                break;
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

void decrypt_blk_file(int offset) {
    //printf("decrypting\n");
    int ch;
    int idx = offset % 8;
    for (size_t i = 0; i < blk_file_size; i++) {
        ch = blk_file[i] ^ key[idx];
        blk_file[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}


void collect_keys() {

    for (int blk_num = 0; blk_num < 99999; blk_num++) {
        size_t blk_offset = 0;
        construct_blk_path(blk_num);
        load_blk_file(blk_file_path);
        printf("looking in %s...\n", blk_file_path);
        decrypt_blk_file(blk_offset);

        int block_offset = 0;

        while(is_magic(block_offset)) {
            int *block_size;
            block_size = (int*)(blk_file + block_offset + 4);
            get_block_hash(block_offset);
            int offset = block_offset;
            offset += 8;

            offset += 4;

            offset += 32;

            offset += 32;

            offset += 4;

            offset += 4;

            offset += 4;

            size_t tx_count = parse_compact_size(offset);
            offset +=  get_compact_size_size(offset);

            for (size_t cur_tx = 0; cur_tx < tx_count; cur_tx++) {

                bool is_segwit = false;
                offset += 4;

                unsigned char *marker = (unsigned char *)(blk_file + offset);
                if (*marker == 0) {
                    unsigned char *flag = (unsigned char *)(blk_file + offset + 1);
                    offset += 2;
                    is_segwit = *flag >= 1; // (*marker == 0 && *flag >= 1);
                }

                size_t input_count = parse_compact_size(offset);
                offset += get_compact_size_size(offset);

                for (size_t i = 0; i < input_count; i++) {
                    offset += 32;

                    offset += 4;

                    size_t script_size = parse_compact_size(offset);
                    offset += get_compact_size_size(offset);
                    offset += script_size;

                    offset += 4;
                }

                size_t output_count = parse_compact_size(offset);
                offset += get_compact_size_size(offset);

                for (size_t i = 0; i < output_count; i++) {
                    offset += 8;

                    size_t pubkey_size = parse_compact_size(offset);
                    offset += get_compact_size_size(offset);
                    if (pubkey_size == 67) {
                        if (blk_file[offset] == 0x41 && blk_file[offset + 1] == 0x04) { //OP_PUSHBYTES_65, uncompressed
                            if (blk_file[offset + 66] == 0xAC) { //OP_CHECKSIG
                                add_key65(offset + 1);
                            }
                        }
                    }
                    if (pubkey_size == 35) {
                        if (blk_file[offset] == 0x21 && (blk_file[offset + 1] == 0x02 || blk_file[offset + 1] == 0x03)) { //OP_PUSHBYTES_33, compressed
                            if (blk_file[offset + 34] == 0xAC) { //OP_CHECKSIG
                                add_key33(offset + 1);
                            }
                        }
                    }
                    offset += pubkey_size;
                }

                if (is_segwit) {
                    for (size_t in = 0; in < input_count; in++) {
                        size_t stack_items = parse_compact_size(offset);
                        offset += get_compact_size_size(offset);
                        for (size_t i = 0; i < stack_items; i++) {
                            size_t stack_item_size = parse_compact_size(offset);
                            offset += get_compact_size_size(offset);
                            offset += stack_item_size;
                        }
                    }
                }

                offset += 4;
            }
            block_offset += 8 + *block_size;

        }
    }
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



void handle_sigint(int sig) {
    show_current_keys();
    exit(0);
}


int main(void) {
    signal(SIGINT, handle_sigint);

    read_xor_key(xor_key_path);


    collect_keys();
    printf("DONE!\n");

    return EXIT_SUCCESS;
}

