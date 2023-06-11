#ifndef ANON_PROXY_H
#define ANON_PROXY_H
// #include "lib-elgamal-mod.h"
#include "lib-misc.h"
#include "lib-mesg.h"

#include <gmp.h>
#include <nettle/sha3.h>
#include <nettle/aes.h>
#include <nettle/ctr.h>

#define anon_proxy_mr_iterations 12

#define anon_proxy_ske_key_size 32
#define anon_proxy_ske_block_size 16
#define anon_proxy_ske_ctx aes256_ctx
#define anon_proxy_ske_set_encypt_key aes256_set_encrypt_key
#define anon_proxy_ske_set_decrypt_key aes256_set_encrypt_key // same as encrypt because of CTR
#define anon_proxy_ske_encrypt aes256_encrypt
#define anon_proxy_ske_block_encrypt ctr_crypt
#define anon_proxy_ske_decrypt aes256_encrypt // same as encrypt because of CTR
#define anon_proxy_ske_block_decrypt ctr_crypt

#define anon_proxy_hash_size 32
#define anon_proxy_hash_ctx sha3_256_ctx
#define anon_proxy_hash_ctx_init sha3_256_init
#define anon_proxy_hash_ctx_update sha3_256_update
#define anon_proxy_hash_ctx_digest sha3_256_digest

enum anon_proxy_lambda
{
    anon_proxy_lambda_80 = 80,
    anon_proxy_lambda_112 = 112,
    anon_proxy_lambda_128 = 128
};

typedef enum anon_proxy_lambda anon_proxy_lambda;

struct anon_proxy_params_struct
{

    size_t p_bits;
    size_t q_bits;
    anon_proxy_lambda lambda;

    // elgamal_mod_params_t elgamal_params;

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
    uint8_t *rekey2_2;
    size_t rekey2_2_size;
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

struct anon_proxy_reencrypted_ciphertext_struct
{
    mpz_t A_1;
    mpz_t B_1;
    uint8_t *D;
    size_t D_size;
    mpz_t U1;
    uint8_t *U2;
    size_t U2_size;
};
typedef struct anon_proxy_reencrypted_ciphertext_struct *anon_proxy_reencrypted_ciphertext_ptr;
typedef struct anon_proxy_reencrypted_ciphertext_struct anon_proxy_reencrypted_ciphertext_t[1];

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output);

void anon_proxy_h2(anon_proxy_params_t params, mpz_t input, uint8_t *output); // Output_size = l == AES_KEY_SIZE == 32

void anon_proxy_h3(anon_proxy_params_t params, mpz_t input, mpz_t output);

void anon_proxy_h4(anon_proxy_params_t params, uint8_t *input, size_t input_size, mpz_t output);

void anon_proxy_plaintext_clear(anon_proxy_plaintext_t plaintext);
void anon_proxy_ciphertext_clear(anon_proxy_ciphertext_t ciphertext);
void anon_proxy_reencrypted_ciphertext_clear(anon_proxy_reencrypted_ciphertext_t ciphertext);
void anon_proxy_pk_clear(anon_proxy_pk_t pk);
void anon_proxy_sk_clear(anon_proxy_sk_t sk);
void anon_proxy_rekey_clear(anon_proxy_rekey_t rekey);
void anon_proxy_params_clear(anon_proxy_params_t params);

void anon_proxy_plaintext_init_manual(anon_proxy_plaintext_t plaintext, uint8_t *m, size_t m_size);
void anon_proxy_plaintext_init_random(gmp_randstate_t prng, anon_proxy_plaintext_t plaintext, size_t m_size);

void anon_proxy_create_h3_ABCD(anon_proxy_params_t params, mpz_t A, mpz_t B, mpz_t C, uint8_t *D, size_t D_size, mpz_t output);
void anon_proxy_keygen_step1(mpz_t x, anon_proxy_params_t params, gmp_randstate_t prng, mpz_t num1, mpz_t num2, size_t h4_n);

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng, anon_proxy_lambda lambda);

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk);

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, anon_proxy_rekey_t rekey);

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext);

void anon_proxy_decrypt_original(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_ciphertext_t ciphertext, anon_proxy_plaintext_t plaintext);

void anon_proxy_reencrypt(anon_proxy_params_t params, anon_proxy_rekey_t rekey, anon_proxy_ciphertext_t ciphertext, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext);

void anon_proxy_decrypt_reencrypted(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext, anon_proxy_plaintext_t plaintext);
#endif // ANON_PROXY_H