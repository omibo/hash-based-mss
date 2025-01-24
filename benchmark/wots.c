// wots.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../params.h"
#include "../wots.h"
#include "../randombytes.h"

#include <time.h>

void print_parameters(xmss_params *params) {
    printf("=== WOTS Parameters ===\n");
    printf("n (hash length in bytes): %d\n", params->n);
    printf("w (Winternitz parameter): %d\n", params->wots_w);
    printf("len_1: %d\n", params->wots_len1);
    printf("len_2: %d\n", params->wots_len2);
    printf("len (total length): %d\n", params->wots_len);
}

void print_lengths(xmss_params *params) {
    printf("\n=== Key and Signature Lengths ===\n");
    printf("Public key length: %d bytes\n", params->wots_sig_bytes);
    printf("Signature length: %d bytes\n", params->wots_sig_bytes);
}

int wots_verify(const xmss_params *params, const unsigned char *sig,
                const unsigned char *msg, const unsigned char *pk)
{
    // Temporary buffer for computed public key
    unsigned char computed_pk[params->wots_sig_bytes];
    uint32_t addr[8] = {0};  // Address buffer
    
    // Generate public key from signature
    wots_pk_from_sig(params, computed_pk, sig, msg, pk, addr);
    
    // Compare computed PK with provided PK
    if (memcmp(computed_pk, pk, params->wots_sig_bytes) != 0) {
        return 0;  // Invalid signature
    }
    
    return 1;  // Valid signature
}

void keygen_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 100000;
    double total_time = 0.0;
    
    printf("\n=== WOTS Key Generation Benchmark ===\n");
    printf("Running %d tests...\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char public_key[params.wots_sig_bytes];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        
        clock_t start = clock();
        wots_pkgen(&params, public_key, seed, pub_seed, addr);
        clock_t end = clock();
        
        total_time += ((double)(end - start)) / CLOCKS_PER_SEC;
    }
    
    double avg_time = total_time / NUM_TESTS;
    printf("\nTotal key generation time: %.8f seconds\n", total_time);
    printf("Average key generation time: %.8f seconds\n", avg_time);
}

void signing_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 100000;
    double total_time = 0.0;
    
    printf("\n=== WOTS Signing Benchmark ===\n");
    printf("Running %d tests...\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char signature[params.wots_sig_bytes];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        
        clock_t start = clock();
        wots_sign(&params, signature, message, seed, pub_seed, addr);
        clock_t end = clock();
        
        total_time += ((double)(end - start)) / CLOCKS_PER_SEC;
    }
    
    double avg_time = total_time / NUM_TESTS;
    printf("\nTotal signing time: %.8f seconds\n", total_time);
    printf("Average signing time: %.8f seconds\n", avg_time);
}

void verification_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    // Test parameters
    const int NUM_TESTS = 100000;
    double total_time = 0.0;
    
    printf("\n=== Verification Time Benchmark ===\n");
    printf("Running %d tests...\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        // Generate new test instance

        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char public_key[params.wots_sig_bytes];
        unsigned char signature[params.wots_sig_bytes];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        // Generate random inputs for this test
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        
        // Generate key pair and signature
        wots_pkgen(&params, public_key, seed, pub_seed, addr);
        wots_sign(&params, signature, message, seed, pub_seed, addr);
        
        // Time verification
        clock_t start = clock();
        int valid = wots_verify(&params, signature, message, public_key);
        clock_t end = clock();
        
        double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
        total_time += time_taken;
        
        // printf("Test %d: %.6f seconds (Valid: %d)\n", i + 1, time_taken, valid);
    }
    
    double avg_time = total_time / NUM_TESTS;
    printf("\n Total verification time: %.8f seconds\n", total_time);
    printf("\nAverage verification time: %.8f seconds\n", avg_time);
}

int main(void) {
    keygen_time();
    signing_time();
    verification_time();
    return 0;
}