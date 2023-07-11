#ifndef ELGAMAL_MOD_H
#define ELGAMAL_MOD_H

#include <stdio.h>
#include <stdbool.h>
#include <gmp.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>
#include <nettle/sha3.h>

#include "lib-powm.h"
#define elgamal_mr_iterations 12

#define elgamal_mod_hash_size 32
#define elgamal_mod_hash_ctx sha3_256_ctx
#define elgamal_mod_hash_ctx_init sha3_256_init
#define elgamal_mod_hash_ctx_update sha3_256_update
#define elgamal_mod_hash_ctx_digest sha3_256_digest

#define elgamal_mod_ske_key_size 32
#define elgamal_mod_ske_block_size 16
#define elgamal_mod_ske_ctx aes256_ctx
#define elgamal_mod_ske_set_encypt_key aes256_set_encrypt_key
#define elgamal_mod_ske_set_decrypt_key aes256_set_encrypt_key // same as encrypt because of CTR
#define elgamal_mod_ske_encrypt aes256_encrypt
#define elgamal_mod_ske_block_encrypt ctr_crypt
#define elgamal_mod_ske_decrypt aes256_encrypt // same as encrypt because of CTR
#define elgamal_mod_ske_block_decrypt ctr_crypt

enum elgamal_mod_lambda
{
    elgamal_mod_lambda_80 = 80,
    elgamal_mod_lambda_112 = 112,
    elgamal_mod_lambda_128 = 128
};
typedef enum elgamal_mod_lambda elgamal_mod_lambda;

struct elgamal_plaintext_struct
{
    uint8_t *m;
    size_t m_size;
};
typedef struct elgamal_plaintext_struct *elgamal_plaintext_ptr;
typedef struct elgamal_plaintext_struct elgamal_plaintext_t[1];

struct elgamal_ciphertext_struct
{
    mpz_t c1;
    uint8_t *c2;
    size_t c2_size;
};
typedef struct elgamal_ciphertext_struct *elgamal_ciphertext_ptr;
typedef struct elgamal_ciphertext_struct elgamal_ciphertext_t[1];

struct elgamal_mod_params_struct
{

    size_t p_bits;
    size_t q_bits;
    size_t lambda;

    struct elgamal_mod_ske_ctx ske_ctx;

    /* elementi pubblici: */
    mpz_t p;
    mpz_t q;
    mpz_t g;

    mpz_t pk;
    mpz_t sk;

    bool use_pp;
    mpz_pp_powm_t g_pp;
    mpz_pp_powm_t pk_pp;
};

typedef struct elgamal_mod_params_struct *elgamal_mod_params_ptr;
typedef struct elgamal_mod_params_struct elgamal_mod_params_t[1];

void elgamal_mod_init(elgamal_mod_params_t params, elgamal_mod_lambda lambda,
                      gmp_randstate_t prng, bool use_pp);

void elgamal_mod_h1(elgamal_mod_params_t params,
                    uint8_t *input, size_t input_size, mpz_t output);

void elgamal_mod_h2(uint8_t *input, size_t input_size, uint8_t *output);

void elgamal_mod_plaintext_init_manual(elgamal_plaintext_t plaintext, uint8_t *input, size_t input_size);

void elgamal_mod_plaintext_init_random(elgamal_plaintext_t plaintext, gmp_randstate_t prng, size_t input_size);

void elgamal_mod_plaintext_clear(elgamal_plaintext_t plaintext);

void elgamal_mod_ciphertext_clear(elgamal_ciphertext_t ciphertext);

void elgamal_mod_params_clear(elgamal_mod_params_t params);

void elgamal_mod_plaintext_print(FILE *file, elgamal_plaintext_t plaintext);

void elgamal_mod_ciphertext_print(FILE *file, elgamal_ciphertext_t ciphertext);

void elgamal_mod_encrypt(elgamal_mod_params_t params, gmp_randstate_t prng,
                         elgamal_plaintext_t plaintext, elgamal_ciphertext_t ciphertext);

void elgamal_mod_decrypt(elgamal_mod_params_t params,
                         elgamal_ciphertext_t ciphertext, elgamal_plaintext_t plaintext);

#endif // ELGAMAL_MOD_H