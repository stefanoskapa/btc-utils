#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

const unsigned char mainnet_magic[] = {0xf9, 0xbe, 0xb4, 0xd9};

unsigned char key[8];
unsigned char blk_file[134217728]; //128 MiB
size_t blk_file_size = 0;

void print_hex(unsigned char *array, size_t len) {
    for (int i = 0; i < len; i++) {
        printf("%02x ", array[i]);
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

void read_block(char *path) {
    FILE *block_file = fopen(path, "rb");

    int ch;
    size_t idx = 0;
    size_t counter = 0;
    while ((ch = fgetc(block_file)) != EOF) {
        unsigned char byte = ch & 0x000000FF;
        byte = (byte ^ key[idx]);
        blk_file[counter] = byte;
        if (idx == 7) idx = 0; else idx++;
        counter++;
    }

    blk_file_size = counter;
    fclose(block_file);
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

void read_xor_key(char *path) {
    FILE *key_file = fopen(path,"rb");
    for (int i = 0; i < 8; i++) {
        unsigned char ch = fgetc(key_file);
        key[i] = ch;
    }
    fclose(key_file);
}


void show_nth_block(int block_num) {
    int block_count = -1;
    for (size_t i = 0; i < blk_file_size; i++) {
        if (is_magic(i)) {
            block_count++;
            if (block_count == block_num) {
                printf("BLOCK %d\n", block_num);
                int *block_size;
                block_size = (int*)(blk_file + i + 4);
                printf("Block size: %d bytes\n", *block_size);   
                show_block_hex(i + 8, i + 8 + *block_size - 1); //skip magic and size (total 8 bytes)
                return;
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
    
    printf("string was %s and number is %d\n", str, (int32_t)result);
    return (int32_t) result;
    
}

int main(int argc, char **argv) {
    if (argc == 1) {
        printf("No block number provided\n");
        exit(1);
    }
    int block_num = parse_int_positive(argv[1]);
    read_xor_key("test_data/xor.dat");
    read_block("test_data/blk00000.dat");
    show_nth_block(block_num);

    return EXIT_SUCCESS;
}

