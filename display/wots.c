// wots.c
#include <stdio.h>
#include <stdlib.h>
#include "../params.h"
#include "../wots.h"
#include "../randombytes.h"

int main(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);

    unsigned char seed[params.n];
    unsigned char pub_seed[params.n];
    unsigned char public_key[params.wots_sig_bytes];
    unsigned char signature[params.wots_sig_bytes];
    unsigned char message[params.n];
    uint32_t addr[8] = {0};

    // Generate random inputs
    randombytes(seed, params.n);
    randombytes(pub_seed, params.n);
    randombytes(message, params.n);
    randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));

    // Generate keys and signature
    wots_pkgen(&params, public_key, seed, pub_seed, addr);
    wots_sign(&params, signature, message, seed, pub_seed, addr);

    // Print parameters
    printf("\n=== WOTS Parameters ===\n");
    printf("n (hash length in bytes): %d\n", params.n);
    printf("w (Winternitz parameter): %d\n", params.wots_w);
    printf("len_1: %d\n", params.wots_len1);
    printf("len_2: %d\n", params.wots_len2);
    printf("len (total length): %d\n", params.wots_len);

    // Print lengths
    printf("\n=== Key and Signature Lengths ===\n");
    printf("Public key length: %d bytes\n", params.wots_sig_bytes);
    printf("Signature length: %d bytes\n", params.wots_sig_bytes);

    // Print hex values
    printf("\n=== Public Seed ===\n");
    for (unsigned int i = 0; i < params.n; i++) {
        printf("%02x", pub_seed[i]);
        if ((i + 1) % 8 == 0) printf("\n");
        else printf(" ");
    }

    printf("\n=== Public Key (first 32 bytes) ===\n");
    for (unsigned int i = 0; i < 32; i++) {
        printf("%02x", public_key[i]);
        if ((i + 1) % 8 == 0) printf("\n");
        else printf(" ");
    }

    return 0;
}