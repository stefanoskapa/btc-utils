#include <stdio.h>
#include <stdlib.h>
#include "wordlist.c"

void help(void) {
    printf("Please provide how many bits of entropy:\n");
    printf("128 -> 12 words\n");
    printf("160 -> 15 words\n");
    printf("192 -> 18 words\n");
    printf("224 -> 21 words\n");
    printf("256 -> 24 words\n");
}

void get_random_bytes(unsigned char *array, size_t size) {
    FILE *file = fopen("/dev/urandom", "r");
    for (size_t i = 0; i < size; i++) {
        int ch = fgetc(file);
        if (ch == EOF) {
            printf("Failed fetching random number\n");
            exit(1);
        }
        array[i] = ch;
    }
    fclose(file);
}

void print_hex(unsigned char *array, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", array[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    
    if (argc != 2) {
        help();
        exit(1);
    }

    int selection = atoi(argv[1]);

    if (selection != 128 && selection != 160 && selection != 192 && selection != 224 && selection != 256) {
        printf("Wrong number of bits.\n");
        help();
        exit(1);
    }

    unsigned char *entropy = malloc(selection / 8);
    if (entropy == NULL) {
        printf("Memory allocation error\n");
        exit(1);
    }
    get_random_bytes(entropy, selection / 8);
    
    print_hex(entropy, selection / 8); 




    exit(EXIT_SUCCESS);

}
