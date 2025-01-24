#include <time.h>
#include <stdio.h>
#include "../params.h"
#include "../pots.h"
#include "../randombytes.h"

void keygen_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 100000;
    double total_time = 0.0;
    
    printf("\n=== POTS Key Generation Benchmark ===\n");
    printf("Running %d tests...\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char sk[params.wots_len1 * params.wots_w * params.n];
        unsigned char pk[params.wots_len1 * params.wots_w * params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        
        clock_t start = clock();
        pots_pkgen(&params, sk, pk, seed, pub_seed, addr);
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
    
    printf("\n=== POTS Signing Benchmark ===\n");
    printf("Running %d tests...\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char sk[params.wots_len1 * params.wots_w * params.n];
        unsigned char pk[params.wots_len1 * params.wots_w * params.n];
        unsigned char sig[params.n * params.wots_len1];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        pots_pkgen(&params, sk, pk, seed, pub_seed, addr);
        
        clock_t start = clock();
        pots_sign(&params, sig, message, sk, pub_seed, addr);
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
    
    const int NUM_TESTS = 100000;
    double total_time = 0.0;
    
    printf("\n=== POTS Verification Benchmark ===\n");
    printf("Running %d tests...\n\n", NUM_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        // Generate fresh test instance
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char sk[params.wots_len1 * params.wots_w * params.n];
        unsigned char pk[params.wots_len1 * params.wots_w * params.n];
        unsigned char sig[params.n * params.wots_len1];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        // Generate random inputs
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));
        
        // Generate keys and signature
        pots_pkgen(&params, sk, pk, seed, pub_seed, addr);
        pots_sign(&params, sig, message, sk, pub_seed, addr);
        
        // Time verification
        clock_t start = clock();
        int valid = pots_ver(&params, sig, message, pk);
        clock_t end = clock();
        
        double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
        total_time += time_taken;
        
        // printf("Test %d: %.6f seconds (Valid: %d)\n", i + 1, time_taken, valid);
    }
    
    double avg_time = total_time / NUM_TESTS;
    printf("\n Total verification time: %.8f seconds\n", total_time);
    printf("\nAverage verification time: %.8f seconds\n", avg_time);
}

int main() {
    keygen_time();
    signing_time();
    verification_time();
    return 0;
}