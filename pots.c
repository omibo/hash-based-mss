#include <stdint.h>
#include <string.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <stdio.h>

#include "utils.h"
#include "hash.h"
#include "pots.h"
#include "hash_address.h"
#include "params.h"

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf_keygen` function.
 */

static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed,
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i, j;
    unsigned char buf[params->n + 32];

    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, params->n);

    for (i = 0; i < params->wots_len1; i++) {
        set_chain_addr(addr, i);
        for (j = 0; j < params->wots_w; j++) {
            set_hash_addr(addr, j);
            addr_to_bytes(buf + params->n, addr);
            prf_keygen(params, outseeds + (i * params->wots_w + j) * params->n, buf, inseed);
        }
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */               

void pots_pkgen(const xmss_params *params, unsigned char *sk,
                      unsigned char *pk, const unsigned char *seed, 
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char buffer[params->n];  
    memset(buffer, 0, params->n); // Initial zero buffer
    unsigned char temp[params->n];
    AES_KEY aes_key;

    expand_seed(params, sk, seed, pub_seed, addr);
    
    // Copy initial zero buffer to first pk position
    memcpy(pk, buffer, 32);

    unsigned int num = 0;
    
    // Perform w iterations
    for (uint32_t chain = 0; chain < params->wots_len1; chain++) {
        for (uint32_t i = 0; i < params->wots_w; i++) {

            uint32_t offset = (chain * params->wots_w + i) * params->n;
            unsigned char iv[16] = {0}; // Initialization vector
            unsigned char ctr[16] = {0};
            // Set up AES key from current sk_i block
            AES_set_encrypt_key(sk + offset, 256, &aes_key);
            
            // Encrypt previous output (or zeros first time)
            CRYPTO_ctr128_encrypt(
                pk + offset,     // input
                temp,                     // output
                params->n,                // length (32 bytes)
                &aes_key,                 // key
                iv,                       // initialization vector
                ctr,                      // counter block
                &num,                     // number of blocks processed
                (block128_f)AES_encrypt   // block cipher
            );
            
            // Store result in next pk block
            memcpy(pk + offset, temp, params->n);
        }
    }

}


/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(const xmss_params *params,
                   int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= params->wots_log_w;
        output[out] = (total >> bits) & (params->wots_w - 1);
        out++;
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void pots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *sk, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len1];
    uint32_t i;

    base_w(params, lengths, params->wots_len1, msg);

    printf("Base-w to sign:\n");
    for (int i = 0; i < params->wots_len1; i++) {
        printf("- %d -", lengths[i]);
    }
    printf("\n\n");

    for (i = 0; i < params->wots_len1; i++) {
        memcpy(
            sig + ((i) * params->n), 
            sk + lengths[i]*params->n + i * params->wots_w * params->n,
            params->n
        );
    }
}

int pots_ver(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *pk)
{
    int lengths[params->wots_len1];
    uint32_t i;

    base_w(params, lengths, params->wots_len1, msg);

    unsigned char buffer[params->n];  
    memset(buffer, 0, params->n); // Initial zero buffer
    unsigned char temp[params->n];
    AES_KEY aes_key;
    
    // Copy initial zero buffer to first pk position
    memcpy(pk, buffer, 32);

    unsigned int num = 0;
    
    // Perform l1 iterations
    for (uint32_t i = 0; i < params->wots_len1; i++) {
        unsigned char iv[16] = {0}; // Initialization vector
        unsigned char ctr[16] = {0};
        // Set up AES key from current sk_i block
        AES_set_encrypt_key(sig + (i * params->n), 256, &aes_key);
        
        // Encrypt previous output (or zeros first time)

        unsigned char input[params->n]; 
        if (lengths[i] == 0) {
            memset(input, 0, params->n);
        } else {
            // Calculate source address
            uint32_t chain_offset = i * params->wots_w * params->n;
            uint32_t pos_offset = (lengths[i]-1) * params->n;
            unsigned char *src = pk + chain_offset + pos_offset;
            
            // Copy data into input array
            memcpy(input, src, params->n);
        }
        CRYPTO_ctr128_encrypt(
            input,     // input
            temp,                     // output
            params->n,                // length (32 bytes)
            &aes_key,                 // key
            iv,                       // initialization vector
            ctr,                      // counter block
            &num,                     // number of blocks processed
            (block128_f)AES_encrypt   // block cipher
        );
        // AES_encrypt(pk + (i * params->n), temp, &aes_key);

        printf("Input Verification:\n");
        for (int j = 0; j < params->n; j++) {
            printf("%02x", input[j]);
        }
        printf("\n\n");

        printf("Temp Verification:\n");
        for (int j = 0; j < params->n; j++) {
            printf("%02x", temp[j]);
        }
        printf("\n\n");

        printf("Key Verification:\n");
        for (int j = 0; j < params->n; j++) {
            printf("%02x", sig + (i * params->n) + j);
        }
        printf("\n\n");
        
        // Store result in next pk block
        if (memcmp(temp, input + params->n, params->n) != 0) {
            printf("Verification failed\n");
            return 0;
        }
    }
    return 1;
}

// /**
//  * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
//  *
//  * Writes the computed public key to 'pk'.
//  */
// void wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
//                       const unsigned char *sig, const unsigned char *msg,
//                       const unsigned char *pub_seed, uint32_t addr[8])
// {
//     int lengths[params->wots_len];
//     uint32_t i;

//     chain_lengths(params, lengths, msg);

//     for (i = 0; i < params->wots_len; i++) {
//         set_chain_addr(addr, i);
//         gen_chain(params, pk + i*params->n, sig + i*params->n,
//                   lengths[i], params->wots_w - 1 - lengths[i], pub_seed, addr);
//     }
// }
