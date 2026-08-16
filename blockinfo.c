#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <openssl/sha.h>
#include <time.h>

#define BLK_MAX_SIZE 134217728
#define MAX_BLOCK_SIZE 4000000
#define HT_CAPACITY 8388608 
#define MINED_BLOCKS 1000000
#define PRIME_MULTIPLIER 5

const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};
const char *xor_key_path = "/mnt/ssd/bitcoin-core/data/blocks/xor.dat";
const char *blk_path = "/mnt/ssd/bitcoin-core/data/blocks";
unsigned char key[8];
unsigned char blk_file[MAX_BLOCK_SIZE];
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

void print_hex_nolf(unsigned char *array, size_t len) {
    for (size_t i = 0; i < len; i++) {
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


bool load_blk_file(char *path, int offset) {
    //printf("Loading %s...\n", path);
    FILE *block_file = fopen(path, "rb");
    if (block_file == NULL) {
        return false;
    }
    fseek(block_file, offset, SEEK_SET);
    blk_file_size = fread(blk_file, 1, MAX_BLOCK_SIZE, block_file);
    //printf("blk file loaded from offset %d (bytes read: %d\n", offset, blk_file_size);
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
    printf("decrypting\n");
    int ch;
    int idx = offset % 8;
    for (size_t i = 0; i < blk_file_size; i++) {
        ch = blk_file[i] ^ key[idx];
        blk_file[i] = ch;
        if (idx == 7) idx = 0; else idx++;
    }
}


void show_block(unsigned char *block_hash, int blk_num, int blk_offset, bool hexdump) {
    //int block_count = -1;

    construct_blk_path(blk_num);
    load_blk_file(blk_file_path, blk_offset);
    decrypt_blk_file(blk_offset);

    print_hex(blk_file, 4);
    int block_offset = 0;
    if (!is_magic(block_offset)) {
        printf("Magic not detected!\n");
        exit(1);
    }
        int *block_size;
        block_size = (int*)(blk_file + block_offset + 4);
        get_block_hash(block_offset);
        if (memcmp(block_hash, sha, 32) == 0) {
            int offset = block_offset;
            printf("\n");
            printf("Metadata\n");
            printf("========\n");
            printf("  Current block hash.: ");
            print_hex_reversed(block_hash, 32);
            printf("  BLK file...........: %s\n", blk_file_path);
            printf("  BLK file offset....: %d\n", block_offset);
            printf("  Block size.........: %d bytes\n", *block_size);   
            printf("Block header\n");
            printf("============\n");
            offset += 8;

            int *version = (int *)(blk_file + offset);
            printf("  Version............: 0x%04x\n", *version);
            offset += 4;

            printf("  Previous Block hash: ");
            print_hex_reversed(blk_file + offset, 32);
            offset += 32;

            printf("  Merkle Root........: ");
            print_hex_reversed(blk_file + offset, 32);
            offset += 32;

            int *epoch = (int *)(blk_file + offset);
            time_t tm = (time_t)*epoch;
            printf("  Time...............: %d (", *epoch);
            show_local_time(tm);
            puts(")");
            offset += 4;

            int *bits = (int *)(blk_file + offset);
            printf("  Bits...............: 0x%08x\n", *bits);
            offset += 4;

            int *nonce = (int *)(blk_file + offset);
            printf("  Nonce..............: 0x%08x\n", *nonce);
            puts("");
            offset += 4;

            printf("Transactions\n");
            printf("============\n");
            size_t tx_count = parse_compact_size(offset);
            printf("  Transaction count..: %lu\n", tx_count);
            offset +=  get_compact_size_size(offset);

            for (size_t cur_tx = 0; cur_tx < tx_count; cur_tx++) {

                if (cur_tx == 0) {
                    printf("  Transaction %lu (Coinbase)\n", cur_tx);                    
                } else {
                    printf("  Transaction %lu\n", cur_tx);
                }

                printf("  --------------------\n");
                bool is_segwit = false;
                unsigned int *tx_version = (unsigned int *)(blk_file + offset);
                printf("    Version.........: %u\n",*tx_version);
                offset += 4;

                unsigned char *marker = (unsigned char *)(blk_file + offset);
                if (*marker == 0) {
                    printf("    Marker..........: %u\n", *marker);
                    unsigned char *flag = (unsigned char *)(blk_file + offset + 1);
                    printf("    Flag............: %u\n", *flag);
                    offset += 2;
                    is_segwit = *flag >= 1; // (*marker == 0 && *flag >= 1);
                }

                size_t input_count = parse_compact_size(offset);
                offset += get_compact_size_size(offset);
                printf("    Inputs..........: %lu\n", input_count);

                for (size_t i = 0; i < input_count; i++) {
                    printf("    Input %lu\n", i);
                    printf("    ---------\n");
                    printf("      TXID...........:");
                    print_hex_reversed(blk_file + offset, 32);
                    offset += 32;

                    unsigned int *vout = (unsigned int *)(blk_file + offset);
                    printf("      VOUT...........: %u\n", *vout);
                    offset += 4;

                    size_t script_size = parse_compact_size(offset);
                    offset += get_compact_size_size(offset);
                    printf("      ScriptSig Size.....: %lu\n", script_size);

                    printf("      --- ScriptSig start ---\n");
                    hex_dump(offset, script_size, "        ");
                    offset += script_size;
                    printf("      --- ScriptSig end ---\n");

                    unsigned int *sequence = (unsigned int *)(blk_file + offset);
                    printf("      Sequence........: %u\n", *sequence);
                    offset += 4;
                }

                size_t output_count = parse_compact_size(offset);
                offset += get_compact_size_size(offset);
                printf("    Outputs..........: %lu\n", output_count);

                for (size_t i = 0; i < output_count; i++) {
                    printf("    Output %lu\n", i);
                    printf("    -----------\n");
                    unsigned long int *amount = (unsigned long int *)(blk_file + offset);
                    printf("      Amount........: %lu\n", *amount);
                    offset += 8;

                    size_t pubkey_size = parse_compact_size(offset);
                    offset += get_compact_size_size(offset);
                    printf("      ScriptPubKey Size: %lu\n", pubkey_size);
                    printf("      --- ScriptPubKey start ---\n");
                    hex_dump(offset, pubkey_size, "\t\t\t");
                    printf("      --- ScriptPubKey end ---\n");
                    offset += pubkey_size;
                }

                if (is_segwit) {
                    printf("    Witness\n");
                    printf("    -------\n");
                    for (size_t in = 0; in < input_count; in++) {
                        printf("      Input %lu witness\n", in);
                        size_t stack_items = parse_compact_size(offset);
                        offset += get_compact_size_size(offset);
                        printf("      Stack Items.......: %lu\n", stack_items);
                        for (size_t i = 0; i < stack_items; i++) {
                            size_t stack_item_size = parse_compact_size(offset);
                            offset += get_compact_size_size(offset);
                            printf("        Size.........: %lu\n", stack_item_size);
                            printf("        --- Item start ---\n");
                            hex_dump(offset, stack_item_size, "          ");
                            printf("        --- Item end ---\n");
                            offset += stack_item_size;
                        }
                    }
                }

                unsigned int *locktime = (unsigned int *)(blk_file + offset);
                printf("    Locktime.........: %u\n", *locktime);
                offset += 4;
            }
            if (hexdump)
                hex_dump(block_offset + 8, *block_size - 1,""); //skip magic and size (total 8 bytes)
            return;
        } else {
            printf("Block was not found!\n");
        }
        //else {
         //   block_offset += 8 + *block_size;
       // }

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
        int offset = hash_table[idx].blk_offset;
        show_block(block_hash_le, hash_table[idx].blk_file_num, offset, hexdump);
    } else {
        printf("Block not found in index!\n");
    }


    return EXIT_SUCCESS;
}

