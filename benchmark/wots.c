// wots.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../params.h"
#include "../wots.h"
#include "../randombytes.h"
#include <math.h>  // Add this for sqrt function

#include <time.h>

#define INNER_TESTS 100

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
    
    const int NUM_TESTS = 1000;
    
    printf("\n=== WOTS Key Generation Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char public_key[params.wots_sig_bytes];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            wots_pkgen(&params, public_key, seed, pub_seed, addr);
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
    
    printf("\n=== WOTS Signing Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char signature[params.wots_sig_bytes];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            wots_sign(&params, signature, message, seed, pub_seed, addr);
            clock_t end = clock();
            
            round_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }
        
        printf("Signing round %d average: %.8f seconds\n", i + 1, round_time / INNER_TESTS);
    }
}

// Add this comparison function before verification_time
static int compare_doubles(const void* a, const void* b) {
    const double *da = (const double *)a;
    const double *db = (const double *)b;
    return (*da > *db) - (*da < *db);
}

void verification_time(void) {
    xmss_params params;
    uint32_t oid = 0x00000001;
    xmss_parse_oid(&params, oid);
    
    const int NUM_TESTS = 10000;
    double *round_averages = malloc(NUM_TESTS * sizeof(double));
    double min_avg = INFINITY;
    double max_avg = 0.0;
    double total_avg = 0.0;
    
    printf("\n=== WOTS Verification Benchmark ===\n");
    printf("Running %d rounds (average of %d tests per round)...\n", NUM_TESTS, INNER_TESTS);
    
    // First collect all round averages
    for (int i = 0; i < NUM_TESTS; i++) {
        double round_time = 0.0;
        unsigned char seed[params.n];
        unsigned char pub_seed[params.n];
        unsigned char public_key[params.wots_sig_bytes];
        unsigned char signature[params.wots_sig_bytes];
        unsigned char message[params.n];
        uint32_t addr[8] = {0};
        
        randombytes(seed, params.n);
        randombytes(pub_seed, params.n);
        randombytes(message, params.n);
        
        // Generate keys and signature once per round
        wots_pkgen(&params, public_key, seed, pub_seed, addr);
        wots_sign(&params, signature, message, seed, pub_seed, addr);
        
        for (int j = 0; j < INNER_TESTS; j++) {
            clock_t start = clock();
            wots_verify(&params, signature, message, public_key);
            clock_t end = clock();
            
            round_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }
        
        double round_avg = round_time / INNER_TESTS;
        round_averages[i] = round_avg;
        
        // Update running statistics
        total_avg += round_avg;
        if (round_avg < min_avg) min_avg = round_avg;
        if (round_avg > max_avg) max_avg = round_avg;
        
        printf("Round %d average: %.8f seconds\n", i + 1, round_avg);
    }
    
    // Calculate final statistics
    double mean = total_avg / NUM_TESTS;
    
    // Calculate variance and standard deviation
    double variance = 0.0;
    for (int i = 0; i < NUM_TESTS; i++) {
        variance += pow(round_averages[i] - mean, 2);
    }
    variance /= NUM_TESTS;
    double std_dev = sqrt(variance);
    
    // Calculate median (sort the averages first)
    qsort(round_averages, NUM_TESTS, sizeof(double), compare_doubles);
    double median = NUM_TESTS % 2 == 0 ? 
        (round_averages[NUM_TESTS/2 - 1] + round_averages[NUM_TESTS/2]) / 2 :
        round_averages[NUM_TESTS/2];
    
    printf("\nFinal Statistics across all rounds:\n");
    printf("  Mean:    %.8f seconds\n", mean);
    printf("  Median:  %.8f seconds\n", median);
    printf("  Min:     %.8f seconds\n", min_avg);
    printf("  Max:     %.8f seconds\n", max_avg);
    printf("  Std Dev: %.8f seconds\n", std_dev);
    printf("  Variance:%.8f seconds²\n", variance);
    
    free(round_averages);
}

int main(void) {
    // keygen_time();
    // signing_time();
    verification_time();
    return 0;
}