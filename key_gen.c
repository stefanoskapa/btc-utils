#include <stdlib.h>
#include <stdio.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>


unsigned char private_key[32];

unsigned char pub_compressed[33];
unsigned char pub_uncompressed[65];

/*
    The private key is a random 256-bit number in the
    range of [1, n-1] where n is the number of points
    on the secp256k1 elliptic curve.
*/
void generate_private_key() {
    FILE *file = fopen("/dev/urandom", "r");
    for (int i = 0; i < 32; i++) {
        unsigned char ch = fgetc(file);
        private_key[i] = ch;
    }
}

void derive_public_key(secp256k1_context *ctx) {
    secp256k1_pubkey public_key;
    if (!secp256k1_ec_pubkey_create(ctx, &public_key, private_key)) {
        fprintf(stderr, "pubkey creation failed\n");
        secp256k1_context_destroy(ctx);
    }

    //compressed: 33 bytes, prefix 0x02/0x03
    size_t len_comp = sizeof(pub_compressed);
    secp256k1_ec_pubkey_serialize(ctx, pub_compressed, &len_comp, &public_key, SECP256K1_EC_COMPRESSED);

    //Uncompressed: 65 bytes, prefix 0x04
    size_t len_uncomp = sizeof(pub_uncompressed);
    secp256k1_ec_pubkey_serialize(ctx, pub_uncompressed, &len_uncomp, &public_key, SECP256K1_EC_UNCOMPRESSED);

}

void hash160(unsigned char *data, size_t len, unsigned char out20[20]) {
    unsigned char sha[SHA256_DIGEST_LENGTH];
    SHA256(data, len, sha);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    RIPEMD160(sha, sizeof(sha), out20);
#pragma GCC diagnostic pop

}

void print_hex(unsigned char *array, size_t size) {
    for (size_t i = 0; i < size; i++)
        printf("%02x", array[i]);
    printf("\n");
}

int main(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    do {
        generate_private_key();
    } while (!secp256k1_ec_seckey_verify(ctx, private_key));

    derive_public_key(ctx);

    puts("Private key:");
    print_hex(private_key, 32);
    puts("Uncompressed public key:");
    print_hex(pub_uncompressed, 65);
    puts("Compressed public key:");
    print_hex(pub_compressed, 33);

    unsigned char h160[20];
    hash160(pub_compressed, sizeof(pub_compressed), h160);
    puts("Compressed HASH160 public key:");
    print_hex(h160, 20);
    hash160(pub_uncompressed, sizeof(pub_compressed), h160);
    puts("Uncompressed HASH160 public key:");
    print_hex(h160, 20);


    secp256k1_context_destroy(ctx);

    exit(EXIT_SUCCESS);
}
