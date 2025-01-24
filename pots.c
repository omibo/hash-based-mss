#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <stdio.h>

#include "utils.h"
#include "hash.h"
#include "pots.h"
#include "hash_address.h"
#include "params.h"


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
          

void pots_pkgen(const xmss_params *params, unsigned char *sk,
                      unsigned char *pk, const unsigned char *seed, 
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    unsigned char temp[params->n];
    
    int outlen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    expand_seed(params, sk, seed, pub_seed, addr);

    for (uint32_t chain = 0; chain < params->wots_len1; chain++) {
        for (uint32_t i = 0; i < params->wots_w; i++) {

            uint32_t offset = (chain * params->wots_w + i) * params->n;
            unsigned char iv[16] = {0};
            unsigned char ctr[16] = {0};
            EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sk + offset, iv);
            
            unsigned char input[params->n]; 
            if (i == 0) {
                memset(input, 0, params->n);
            } else {
                unsigned char *src = pk + offset - params->n;
                memcpy(input, src, params->n);
            }
            EVP_EncryptUpdate(ctx, temp, &outlen, input, params->n);
            
            memcpy(pk + offset, temp, params->n);
        }
    }
    EVP_CIPHER_CTX_free(ctx);

}

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


void pots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *sk, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len1];
    uint32_t i;

    base_w(params, lengths, params->wots_len1, msg);

    for (i = 0; i < params->wots_len1; i++) {
        memcpy(
            sig + ((i) * params->n), 
            sk + lengths[i]*params->n + i * params->wots_w * params->n,
            params->n
        );
    }
}

int pots_ver(const xmss_params *params,
               const unsigned char *sig, const unsigned char *msg,
               const unsigned char *pk)
{
    int lengths[params->wots_len1];
    base_w(params, lengths, params->wots_len1, msg);

    unsigned char temp[params->n];
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;
    
    for (uint32_t i = 0; i < params->wots_len1; i++) {
        unsigned char iv[16] = {0}; // Initialization vector
        unsigned char ctr[16] = {0};

        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, sig + (i * params->n), iv);
        
        unsigned char input[params->n]; 
        if (lengths[i] == 0) {
            memset(input, 0, params->n);
        } else {
            uint32_t chain_offset = i * params->wots_w * params->n;
            uint32_t pos_offset = (lengths[i]-1) * params->n;
            unsigned char *src = pk + chain_offset + pos_offset;
            memcpy(input, src, params->n);
        }

        EVP_EncryptUpdate(ctx, temp, &outlen, input, params->n);

        unsigned char *next_pk = pk + i * params->wots_w * params->n + (lengths[i]) * params->n;
        
        if (memcmp(temp, next_pk, params->n) != 0) {
            printf("Verification failed\n");
            return 0;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}
