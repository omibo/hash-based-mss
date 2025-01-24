#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../params.h"
#include "../xmss.h"
#include "../xmss_commons.h"
#include "../xmss_core.h"
#include "../randombytes.h"

#define XMSS_SIGNATURES 15    // Number of messages to sign
#define XMSS_MLEN 32         // Message length in bytes
#define XMSS_VARIANT "XMSS-SHA2_10_256"  // Replace with your variant

int main() {
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i;

    // Convert variant string to OID
    if (xmss_str_to_oid(&oid, XMSS_VARIANT)) {
        printf("Failed to convert variant string to OID.\n");
        return -1;
    }

    // Parse OID to initialize parameters
    if (xmss_parse_oid(&params, oid)) {
        printf("Failed to parse OID.\n");
        return -1;
    }

    // printf("XMSS Parameters:\n");
    // printf("  - height: %d\n", params.tree_height);

    // Allocate key and message buffers
    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    if (m == NULL || sm == NULL || mout == NULL) {
        printf("Failed to allocate memory.\n");
        return -1;
    }

    // Generate random message
    randombytes(m, XMSS_MLEN);

    // Generate key pair
    printf("Generating key pair...\n");
    if (xmss_keypair(pk, sk, oid)) {
        printf("Failed to generate key pair.\n");
        return -1;
    }

    printf("Testing %d %s signatures...\n\n", XMSS_SIGNATURES, XMSS_VARIANT);

    double total_sign_time = 0.0;

    for (i = 0; i < XMSS_SIGNATURES; i++) {
        printf("  - Iteration #%d:\n", i + 1);

        // Measure time taken to sign
        clock_t start = clock();
        if (xmss_sign(sk, sm, &smlen, m, XMSS_MLEN)) {
            printf("  X Error signing message.\n");
            ret = -1;
            break;
        }
        clock_t end = clock();

        double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
        total_sign_time += time_taken;

        printf("    Signature time: %.3f seconds\n", time_taken);

        if (smlen != params.sig_bytes + XMSS_MLEN) {
            printf("  X Signature length incorrect [%llu != %u]!\n", smlen, params.sig_bytes + XMSS_MLEN);
            ret = -1;
        } else {
            printf("    Signature length as expected [%llu bytes].\n", smlen);
        }

        // Verify signature
        if (xmss_sign_open(mout, &mlen, sm, smlen, pk)) {
            printf("  X Verification failed!\n");
            ret = -1;
            break;
        } else {
            printf("    Verification succeeded.\n");
        }

        printf("\n");
    }

    if (ret == 0) {
        printf("Total signing time: %.3f seconds\n", total_sign_time);
        printf("Average signing time: %.3f seconds\n", total_sign_time / XMSS_SIGNATURES);
    }

    // Clean up
    free(m);
    free(sm);
    free(mout);

    return ret;
}