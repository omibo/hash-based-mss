#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include "../params.h"
#include "../pots.h"
#include "../randombytes.h"

#define INNER_TESTS 1000

void keygen_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 1000;
    
    printf("\n=== POTS Key Generation Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char sk[params.wots_len1 * params.wots_w * params.n];
        unsigned char pk[params.wots_len1 * params.wots_w * params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            pots_pkgen(&params, sk, pk, seed, pub_seed, addr);
            clock_t end = clock();
            
            round_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }
        
        printf("Keygen round %d average: %.8f seconds\n", i + 1, round_time / INNER_TESTS);
    }
}

void signing_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 1000;
    
    printf("\n=== POTS Signing Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
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
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            pots_sign(&params, sig, message, sk, pub_seed, addr);
            clock_t end = clock();
            
            round_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }
        
        printf("Signing round %d average: %.8f seconds\n", i + 1, round_time / INNER_TESTS);
    }
}

void verification_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 1000;
    
    printf("\n=== POTS Verification Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
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
        randombytes((unsigned char *)addr, 8 * sizeof(uint32_t));
        
        // Generate keys and signature once per round
        pots_pkgen(&params, sk, pk, seed, pub_seed, addr);
        pots_sign(&params, sig, message, sk, pub_seed, addr);
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            pots_ver(&params, sig, message, pk);
            clock_t end = clock();
            
            round_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }
        
        printf("Verification round %d average: %.8f seconds\n", 
               i + 1, round_time / INNER_TESTS);
    }
}

int main() {
    // keygen_time();
    // signing_time();
    // verification_time();
    return 0;
}