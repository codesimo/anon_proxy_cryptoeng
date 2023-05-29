#ifndef ANON_PROXY_H
#define ANON_PROXY_H
#include "elgamal-mod.h"

#define anon_proxy_mr_iterations 12

#define anon_proxy_hash_size 32
#define anon_proxy_hash_ctx sha3_256_ctx
#define anon_proxy_hash_ctx_init sha3_256_init
#define anon_proxy_hash_ctx_update sha3_256_update
#define anon_proxy_hash_ctx_digest sha3_256_digest

struct anon_proxy_params_struct
{

    size_t p_bits;
    size_t q_bits;
    size_t lambda;

    elgamal_mod_params_t elgamal_params;

    /* elementi pubblici: */
    mpz_t p;
    mpz_t q;
    mpz_t g;
};

typedef struct anon_proxy_params_struct *anon_proxy_params_ptr;
typedef struct anon_proxy_params_struct anon_proxy_params_t[1];

struct anon_proxy_sk_struct
{
    mpz_t sk;
};
typedef struct anon_proxy_sk_struct *anon_proxy_sk_ptr;
typedef struct anon_proxy_sk_struct anon_proxy_sk_t[1];

struct anon_proxy_pk_struct
{
    mpz_t pk1;
    mpz_t pk2;
};
typedef struct anon_proxy_pk_struct *anon_proxy_pk_ptr;
typedef struct anon_proxy_pk_struct anon_proxy_pk_t[1];

struct anon_proxy_rekey_struct
{
    mpz_t rekey1[2];
    mpz_t rekey2_1;
    elgamal_ciphertext_t rekey2_2;
};

typedef struct anon_proxy_rekey_struct *anon_proxy_rekey_ptr;
typedef struct anon_proxy_rekey_struct anon_proxy_rekey_t[1];

struct anon_proxy_plaintext_struct
{
    uint8_t *m;
    size_t m_size;
};
typedef struct anon_proxy_plaintext_struct *anon_proxy_plaintext_ptr;
typedef struct anon_proxy_plaintext_struct anon_proxy_plaintext_t[1];

struct anon_proxy_ciphertext_struct
{
    mpz_t A;
    mpz_t B;
    mpz_t C;
    uint8_t k[anon_proxy_hash_size];
    uint8_t *D;
    size_t D_size;
    mpz_t S;
};

typedef struct anon_proxy_ciphertext_struct *anon_proxy_ciphertext_ptr;
typedef struct anon_proxy_ciphertext_struct anon_proxy_ciphertext_t[1];

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output);

void anon_proxy_h2(anon_proxy_params_t params, mpz_t input, uint8_t *output); // Output_size = l == AES_KEY_SIZE == 32

void anon_proxy_h3(anon_proxy_params_t params, mpz_t input, mpz_t output);

void anon_proxy_h4(anon_proxy_params_t params, uint8_t *input, size_t input_size, mpz_t output);

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng);

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk);

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, elgamal_mod_params_t elgamal_mod_params, anon_proxy_rekey_t rekey);

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext);

#endif // ANON_PROXY_H