#include <string.h>

#include "anon-proxy.h"

void anon_proxy_h1(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    uint8_t padding[1];
    padding[0] = 0x00;
    anon_proxy_hash_ctx_update(&ctx, 1, padding);
    anon_proxy_hash_ctx_update(&ctx, input_size, input);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_h2(anon_proxy_params_t params, mpz_t input, uint8_t *output)
{
    size_t input_size = mpz_sizeinbase(input, 256);
    uint8_t input_bytes[input_size];

    mpz_export(input_bytes, NULL, 1, 1, 0, 0, input);

    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    anon_proxy_hash_ctx_update(&ctx, input_size, input_bytes);
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_ske_key_size, output);
}

void anon_proxy_h3(anon_proxy_params_t params, mpz_t input, mpz_t output)
{
    mpz_mod(output, input, params->p);
    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_h4(anon_proxy_params_t params,
                   uint8_t *input, size_t input_size, mpz_t output)
{
    struct anon_proxy_hash_ctx ctx;
    anon_proxy_hash_ctx_init(&ctx);
    uint8_t padding[1];
    padding[0] = 0x01;
    anon_proxy_hash_ctx_update(&ctx, 1, padding);
    anon_proxy_hash_ctx_update(&ctx, input_size, input);

    uint8_t digest[anon_proxy_hash_size];
    anon_proxy_hash_ctx_digest(&ctx, anon_proxy_hash_size, digest);

    mpz_import(output, anon_proxy_hash_size, 1, 1, 0, 0, digest);
    mpz_mod(output, output, params->p);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng, anon_proxy_lambda lambda)
{
    assert(params);
    assert(prng);
    assert((lambda == 80) || (lambda == 112) || (lambda == 128));

    mpz_t k, a, tmp;
    mpz_inits(k, a, tmp, NULL);
    mpz_inits(params->p, params->q, params->g, NULL);
    params->lambda = lambda;
    switch (lambda)
    {
    case 80:
        params->p_bits = 1024;
        break;
    case 112:
        params->p_bits = 2048;
        break;
    case 128:
        params->p_bits = 3072;
        break;
    }
    params->q_bits = lambda * 2;

    /* q primo lungo q_bits */
    do
    {
        mpz_urandomb(params->q, prng, params->q_bits);
    } while ((mpz_sizeinbase(params->q, 2) < params->q_bits) ||
             !mpz_probab_prime_p(params->q, anon_proxy_mr_iterations));

    /* p=k*q+1 primo lungo p_bits */
    do
    {
        unsigned int k_bits = params->p_bits - params->q_bits;

        /* k lungo k_bits */
        do
            mpz_urandomb(k, prng, k_bits);
        while (mpz_sizeinbase(k, 2) < k_bits);

        /* p = k*q + 1 */
        mpz_mul(params->p, params->q, k);
        mpz_add_ui(params->p, params->p, 1);
    } while ((mpz_sizeinbase(params->p, 2) < params->p_bits) ||
             !mpz_probab_prime_p(params->p, anon_proxy_mr_iterations));

    /* g generatore del sottogruppo di ordine q: g!=1 && g^q=1 */
    do
    {
        mpz_urandomm(a, prng, params->p);

        /* g = a^k mod p */
        mpz_powm(params->g, a, k, params->p);

        /* tmp = g^q mod p */
        mpz_powm(tmp, params->g, params->q, params->p);
    } while ((mpz_cmp_ui(params->g, 1) == 0) || (mpz_cmp_ui(tmp, 1) != 0));

    pmesg(msg_very_verbose, "-------------Initialization completed-------------");
    pmesg_mpz(msg_very_verbose, "modulo", params->p);
    pmesg_mpz(msg_very_verbose, "ordine del sottogruppo", params->q);
    pmesg_mpz(msg_very_verbose, "generatore del sottogruppo", params->g);
}

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk)
{
    mpz_inits(sk->sk, pk->pk1, pk->pk2, NULL);

    mpz_urandomm(sk->sk, prng, params->q);
    mpz_powm(pk->pk1, params->g, sk->sk, params->p);

    size_t sk_size = mpz_sizeinbase(sk->sk, 256);

    uint8_t h4_0[sk_size + 1];
    uint8_t h4_1[sk_size + 1];
    mpz_export(h4_0, NULL, 1, 1, 0, 0, sk->sk);
    mpz_export(h4_1, NULL, 1, 1, 0, 0, sk->sk);
    h4_0[sk_size] = 0;
    h4_1[sk_size] = 1;

    mpz_t h4_0_out, h4_1_out;
    mpz_inits(h4_0_out, h4_1_out, NULL);

    anon_proxy_h4(params, h4_0, sk_size + 1, h4_0_out);
    anon_proxy_h4(params, h4_1, sk_size + 1, h4_1_out);

    mpz_mul(h4_1_out, sk->sk, h4_1_out);
    mpz_add(h4_0_out, h4_0_out, h4_1_out);
    mpz_powm(pk->pk2, params->g, h4_0_out, params->p);

    pmesg(msg_normal, "-------------Key generation completed-------------");
    pmesg_mpz(msg_verbose, "sk", sk->sk);
    pmesg_mpz(msg_verbose, "pk1", pk->pk1);
    pmesg_mpz(msg_verbose, "pk2", pk->pk2);

    mpz_clears(h4_0_out, h4_1_out, NULL);
}

void anon_proxy_keygen_step1(mpz_t x, anon_proxy_params_t params, gmp_randstate_t prng, mpz_t num1, mpz_t num2, size_t h4_n)
{
    size_t sk_size = mpz_sizeinbase(x, 256);
    uint8_t h4[sk_size + 1];
    mpz_export(h4, NULL, 1, 1, 0, 0, x);
    h4[sk_size] = h4_n;

    mpz_t h4_out;
    mpz_init(h4_out);
    anon_proxy_h4(params, h4, sk_size + 1, h4_out);

    mpz_t test;
    mpz_init(test);

    mpz_mod(h4_out, h4_out, params->q);
    do
    {
        mpz_urandomm(num2, prng, params->q);
    } while (mpz_sizeinbase(num2, 2) != params->q_bits || mpz_cmp_ui(num2, 0) == 0);

    mpz_invert(num1, num2, params->q);

    mpz_mul(num1, num1, h4_out);
    mpz_mod(num1, num1, params->q);

    mpz_mul(test, num1, num2);

    mpz_mod(test, test, params->q);
    assert(mpz_cmp(test, h4_out) == 0);
    mpz_clears(h4_out, test, NULL);
}

void anon_proxy_create_r_a2_b2(anon_proxy_params_t params, mpz_t r, mpz_t a2, mpz_t b2, uint8_t **r_a2_b2, size_t *r_a2_b2_size)
{
    size_t r_size = mpz_sizeinbase(r, 256);
    size_t a2_size = mpz_sizeinbase(a2, 256);
    size_t b2_size = mpz_sizeinbase(b2, 256);

    // r||a2||b2
    *r_a2_b2_size = r_size + a2_size + b2_size;
    *r_a2_b2 = malloc(*r_a2_b2_size);
    memset(*r_a2_b2, 0, *r_a2_b2_size);

    size_t test_size;
    mpz_export(*r_a2_b2, &test_size, 1, 1, 0, 0, r);
    assert(test_size == r_size);
    mpz_export(*r_a2_b2 + r_size, &test_size, 1, 1, 0, 0, a2);
    assert(test_size == a2_size);
    mpz_export(*r_a2_b2 + r_size + a2_size, &test_size, 1, 1, 0, 0, b2);
    assert(test_size == b2_size);

    pmesg_hex(msg_normal, "r||a2||b2", *r_a2_b2_size, *r_a2_b2);
    mpz_clear(r);
}

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, anon_proxy_rekey_t rekey)
{
    pmesg(msg_verbose, "---------------------Rekeygen---------------------");

    mpz_t a1, a2, b1, b2;
    mpz_inits(a1, a2, b1, b2, NULL);

    anon_proxy_keygen_step1(sk->sk, params, prng, a1, a2, 0);
    anon_proxy_keygen_step1(sk->sk, params, prng, b1, b2, 1);

    mpz_init_set(rekey->rekey1[0], a1);
    mpz_init_set(rekey->rekey1[1], b1);

    pmesg_mpz(msg_verbose, "a1", rekey->rekey1[0]);
    pmesg_mpz(msg_verbose, "b1", rekey->rekey1[1]);

    pmesg_mpz(msg_normal, "a2", a2);
    pmesg_mpz(msg_normal, "b2", b2);

    // random r
    mpz_t r;
    mpz_init(r);
    do
    {
        mpz_urandomm(r, prng, params->q);
    } while (mpz_sizeinbase(r, 2) != params->q_bits || mpz_cmp_ui(r, 0) == 0);

    pmesg_mpz(msg_normal, "r", r);

    uint8_t *r_a2_b2 = NULL;
    size_t r_a2_b2_size = 0;

    anon_proxy_create_r_a2_b2(params, r, a2, b2, &r_a2_b2, &r_a2_b2_size);

    // H1(r||a2||b2)
    mpz_t h1_output;
    mpz_init(h1_output);
    pmesg_hex(msg_normal, "WEOWFKEOKFW", r_a2_b2_size, r_a2_b2);

    anon_proxy_h1(params, r_a2_b2, r_a2_b2_size, h1_output);

    // rk1 = (a1, b1)
    mpz_init_set(rekey->rekey1[0], a1);
    mpz_init_set(rekey->rekey1[1], b1);

    // mpz_init(rekey->rekey2_1);
    //  rk2 = (g^h1, ...)
    mpz_powm(rekey->rekey2_1, params->g, h1_output, params->p);

    mpz_t h2_input;
    mpz_init(h2_input);
    // pk1^H1_output
    mpz_powm(h2_input, pk->pk1, h1_output, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    anon_proxy_h2(params, h2_input, h2_output);

    mpz_clears(h1_output, h2_input, NULL);

    rekey->rekey2_2_size = r_a2_b2_size;
    rekey->rekey2_2 = malloc(rekey->rekey2_2_size);
    printf("AAAAG\n");
    struct anon_proxy_ske_ctx ctx;
    anon_proxy_ske_set_encypt_key(&(ctx), h2_output);

    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);

    anon_proxy_ske_block_encrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_encrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 rekey->rekey2_2_size,
                                 rekey->rekey2_2,
                                 r_a2_b2);

    pmesg_mpz(msg_verbose, "rk2_1 (U1)", rekey->rekey2_1);
    pmesg_hex(msg_verbose, "rk2_2 (U2)", rekey->rekey2_2_size, rekey->rekey2_2);

    free(r_a2_b2);
    mpz_clears(a1, a2, b1, b2, NULL);
}

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext)
{
    pmesg(msg_verbose, "--------------------Encryption--------------------");
    // random r, r_1 that are different from 0 and from each other
    mpz_t r, r_1;
    mpz_inits(r, r_1, NULL);
    do
    {
        mpz_urandomm(r, prng, params->q);
        mpz_urandomm(r_1, prng, params->q);
    } while (mpz_cmp(r, r_1) == 0 || mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(r_1, 0) == 0);

    pmesg_mpz(msg_very_verbose, "r", r);
    pmesg_mpz(msg_very_verbose, "r_1", r_1);

    mpz_inits(ciphertext->A, ciphertext->B, ciphertext->C, NULL);
    mpz_powm(ciphertext->A, params->g, r, params->p);
    mpz_powm(ciphertext->B, pk->pk1, r, params->p);
    mpz_powm(ciphertext->C, params->g, r_1, params->p);

    pmesg_mpz(msg_verbose, "A", ciphertext->A);
    pmesg_mpz(msg_verbose, "B", ciphertext->B);
    pmesg_mpz(msg_verbose, "C", ciphertext->C);

    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, pk->pk2, r, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];

    anon_proxy_h2(params, h2_input, h2_output);

    mpz_clear(h2_input);

    pmesg_hex(msg_very_verbose, "K IN ENC()", anon_proxy_ske_key_size, h2_output);

    struct anon_proxy_ske_ctx ctx;
    anon_proxy_ske_set_encypt_key(&(ctx), h2_output);

    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);

    ciphertext->D_size = plaintext->m_size;
    ciphertext->D = malloc(ciphertext->D_size);

    anon_proxy_ske_block_encrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_encrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 plaintext->m_size,
                                 ciphertext->D,
                                 plaintext->m);

    pmesg_hex(msg_verbose, "D", ciphertext->D_size, ciphertext->D);

    size_t A_size = mpz_sizeinbase(ciphertext->A, 256);
    size_t B_size = mpz_sizeinbase(ciphertext->B, 256);
    size_t C_size = mpz_sizeinbase(ciphertext->C, 256);

    uint8_t h3_input[A_size + B_size + C_size + ciphertext->D_size];
    mpz_export(h3_input, NULL, 1, 1, 0, 0, ciphertext->A);
    mpz_export(h3_input + A_size, NULL, 1, 1, 0, 0, ciphertext->B);
    mpz_export(h3_input + A_size + B_size, NULL, 1, 1, 0, 0, ciphertext->C);
    memcpy(h3_input + A_size + B_size + C_size, ciphertext->D, ciphertext->D_size);

    mpz_t h3_output;
    mpz_init(h3_output);
    mpz_t h3_input_mpz;
    mpz_init(h3_input_mpz);
    mpz_import(h3_input_mpz, A_size + B_size + C_size + ciphertext->D_size, 1, 1, 0, 0, h3_input);

    anon_proxy_h3(params, h3_input_mpz, h3_output);

    mpz_mul(ciphertext->S, h3_output, r);
    mpz_add(ciphertext->S, ciphertext->S, r_1);
    mpz_mod(ciphertext->S, ciphertext->S, params->q);

    pmesg_mpz(msg_verbose, "S", ciphertext->S);

    mpz_clears(r, r_1, h3_output, h3_input_mpz, NULL);
}

void anon_proxy_decrypt_original(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_ciphertext_t ciphertext, anon_proxy_plaintext_t plaintext)
{
    pmesg(msg_verbose, "--------------------Decryption--------------------");
    size_t A_size = mpz_sizeinbase(ciphertext->A, 256);
    size_t B_size = mpz_sizeinbase(ciphertext->B, 256);
    size_t C_size = mpz_sizeinbase(ciphertext->C, 256);

    uint8_t h3_input[A_size + B_size + C_size + ciphertext->D_size];
    mpz_export(h3_input, NULL, 1, 1, 0, 0, ciphertext->A);
    mpz_export(h3_input + A_size, NULL, 1, 1, 0, 0, ciphertext->B);
    mpz_export(h3_input + A_size + B_size, NULL, 1, 1, 0, 0, ciphertext->C);
    memcpy(h3_input + A_size + B_size + C_size, ciphertext->D, ciphertext->D_size);

    mpz_t h3_output;
    mpz_init(h3_output);
    mpz_t h3_input_mpz;
    mpz_init(h3_input_mpz);
    mpz_import(h3_input_mpz, A_size + B_size + C_size + ciphertext->D_size, 1, 1, 0, 0, h3_input);

    anon_proxy_h3(params, h3_input_mpz, h3_output);

    mpz_t h3_output_check_1;
    mpz_init(h3_output_check_1);
    mpz_powm(h3_output_check_1, ciphertext->A, h3_output, params->p);
    mpz_mul(h3_output_check_1, h3_output_check_1, ciphertext->C);
    mpz_mod(h3_output_check_1, h3_output_check_1, params->p);

    pmesg_mpz(msg_very_verbose, "h3_output_check_1", h3_output_check_1);

    mpz_t h3_output_check_2;
    mpz_init(h3_output_check_2);
    mpz_powm(h3_output_check_2, params->g, ciphertext->S, params->p);

    assert(mpz_cmp(h3_output_check_1, h3_output_check_2) == 0);
    pmesg(msg_very_verbose, "h3_output_check_1 == h3_output_check_2");

    mpz_t h4_0, h4_1;
    mpz_inits(h4_0, h4_1, NULL);

    size_t sk_size = mpz_sizeinbase(sk->sk, 256);
    uint8_t sk_0[sk_size + 1];
    uint8_t sk_1[sk_size + 1];
    mpz_export(sk_0, NULL, 1, 1, 0, 0, sk->sk);
    mpz_export(sk_1, NULL, 1, 1, 0, 0, sk->sk);
    sk_0[sk_size] = 0;
    sk_1[sk_size] = 1;

    anon_proxy_h4(params, sk_0, sk_size + 1, h4_0);
    anon_proxy_h4(params, sk_1, sk_size + 1, h4_1);

    mpz_t a_pow, b_pow, h2_input;
    mpz_inits(a_pow, b_pow, NULL);
    mpz_powm(a_pow, ciphertext->A, h4_0, params->p);
    mpz_powm(b_pow, ciphertext->B, h4_1, params->p);
    mpz_mul(h2_input, a_pow, b_pow);
    mpz_mod(h2_input, h2_input, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    memset(h2_output, 0, anon_proxy_ske_key_size);
    anon_proxy_h2(params, h2_input, h2_output);
    pmesg_hex(msg_very_verbose, "key", anon_proxy_ske_key_size, h2_output);

    struct anon_proxy_ske_ctx ctx;
    anon_proxy_ske_set_decrypt_key(&(ctx), h2_output);
    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);
    plaintext->m_size = ciphertext->D_size;
    plaintext->m = malloc(plaintext->m_size);

    anon_proxy_ske_block_decrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_decrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 ciphertext->D_size,
                                 plaintext->m,
                                 ciphertext->D);

    pmesg_hex(msg_verbose, "decrypted", plaintext->m_size, plaintext->m);
}

void anon_proxy_reencrypt(anon_proxy_params_t params, anon_proxy_rekey_t rekey, anon_proxy_ciphertext_t ciphertext, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext)
{
    pmesg(msg_verbose, "-------------------Reencryption-------------------");
    size_t A_size = mpz_sizeinbase(ciphertext->A, 256);
    size_t B_size = mpz_sizeinbase(ciphertext->B, 256);
    size_t C_size = mpz_sizeinbase(ciphertext->C, 256);

    uint8_t h3_input[A_size + B_size + C_size + ciphertext->D_size];
    mpz_export(h3_input, NULL, 1, 1, 0, 0, ciphertext->A);
    mpz_export(h3_input + A_size, NULL, 1, 1, 0, 0, ciphertext->B);
    mpz_export(h3_input + A_size + B_size, NULL, 1, 1, 0, 0, ciphertext->C);

    memcpy(h3_input + A_size + B_size + C_size, ciphertext->D, ciphertext->D_size);

    mpz_t h3_output;
    mpz_init(h3_output);

    mpz_t h3_input_mpz;
    mpz_init(h3_input_mpz);

    mpz_import(h3_input_mpz, A_size + B_size + C_size + ciphertext->D_size, 1, 1, 0, 0, h3_input);

    anon_proxy_h3(params, h3_input_mpz, h3_output);
    mpz_clear(h3_input_mpz);

    mpz_t h3_output_check_1;
    mpz_init(h3_output_check_1);

    mpz_powm(h3_output_check_1, ciphertext->A, h3_output, params->p);
    mpz_mul(h3_output_check_1, h3_output_check_1, ciphertext->C);
    mpz_mod(h3_output_check_1, h3_output_check_1, params->p);

    pmesg_mpz(msg_very_verbose, "h3_output_check_1", h3_output_check_1);

    mpz_t h3_output_check_2;
    mpz_init(h3_output_check_2);
    mpz_powm(h3_output_check_2, params->g, ciphertext->S, params->p);

    assert(mpz_cmp(h3_output_check_1, h3_output_check_2) == 0);
    pmesg(msg_very_verbose, "h3_output_check_1 == h3_output_check_2");

    mpz_t A_1, B_1;
    mpz_inits(A_1, B_1, NULL);
    mpz_powm(A_1, ciphertext->A, rekey->rekey1[0], params->p);
    mpz_powm(B_1, ciphertext->B, rekey->rekey1[1], params->p);

    mpz_init_set(reencrypted_ciphertext->A_1, A_1);
    mpz_init_set(reencrypted_ciphertext->B_1, B_1);

    reencrypted_ciphertext->D_size = ciphertext->D_size;
    reencrypted_ciphertext->D = malloc(reencrypted_ciphertext->D_size);
    memcpy(reencrypted_ciphertext->D, ciphertext->D, reencrypted_ciphertext->D_size);

    mpz_init_set(reencrypted_ciphertext->U1, rekey->rekey2_1);

    reencrypted_ciphertext->U2_size = rekey->rekey2_2_size;
    reencrypted_ciphertext->U2 = malloc(reencrypted_ciphertext->U2_size);
    memcpy(reencrypted_ciphertext->U2, rekey->rekey2_2, reencrypted_ciphertext->U2_size);

    mpz_clears(h3_output, A_1, B_1, NULL);
    mpz_clears(h3_output_check_1, h3_output_check_2, NULL);

    pmesg_mpz(msg_normal, "A_1", reencrypted_ciphertext->A_1);
    pmesg_mpz(msg_normal, "B_1", reencrypted_ciphertext->B_1);
    pmesg_hex(msg_normal, "D", reencrypted_ciphertext->D_size, reencrypted_ciphertext->D);
    pmesg_mpz(msg_normal, "U1", reencrypted_ciphertext->U1);
    pmesg_hex(msg_normal, "U2", reencrypted_ciphertext->U2_size, reencrypted_ciphertext->U2);
}

void anon_proxy_decrypt_reencrypted(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext, anon_proxy_plaintext_t plaintext)
{
    pmesg(msg_verbose, "----------------Decrypt Reencrypted---------------");
    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, reencrypted_ciphertext->U1, sk->sk, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    memset(h2_output, 0, anon_proxy_ske_key_size);
    anon_proxy_h2(params, h2_input, h2_output);

    uint8_t r_a2_b2[reencrypted_ciphertext->U2_size];
    memset(r_a2_b2, 0, reencrypted_ciphertext->U2_size);

    struct anon_proxy_ske_ctx ctx;
    uint8_t ctr[anon_proxy_ske_block_size];
    memset(ctr, 0, anon_proxy_ske_block_size);

    anon_proxy_ske_set_decrypt_key(&(ctx), h2_output);
    anon_proxy_ske_block_decrypt(&(ctx),
                                 (nettle_cipher_func *)anon_proxy_ske_decrypt,
                                 anon_proxy_ske_block_size,
                                 ctr,
                                 reencrypted_ciphertext->U2_size,
                                 r_a2_b2,
                                 reencrypted_ciphertext->U2);

    mpz_t h1_output;
    mpz_init(h1_output);

    anon_proxy_h1(params, r_a2_b2, reencrypted_ciphertext->U2_size, h1_output);

    mpz_t h1_output_check;
    mpz_init(h1_output_check);
    mpz_powm(h1_output_check, params->g, h1_output, params->p);

    pmesg_mpz(msg_very_verbose, "h1_output_check", h1_output_check);
    pmesg_mpz(msg_very_verbose, "U1", reencrypted_ciphertext->U1);

    assert(mpz_cmp(h1_output_check, reencrypted_ciphertext->U1) == 0);
    pmesg(msg_very_verbose, "h1_output_check == U1");

    pmesg_hex(msg_normal, "r_a2_b2  ", reencrypted_ciphertext->U2_size, r_a2_b2);

    size_t q_bytes = params->q_bits / 8;
    mpz_t r, a2, b2;

    mpz_inits(r, a2, b2, NULL);

    mpz_import(r, q_bytes, 1, 1, 0, 0, r_a2_b2);
    mpz_import(a2, q_bytes, 1, 1, 0, 0, r_a2_b2 + q_bytes);
    mpz_import(b2, q_bytes, 1, 1, 0, 0, r_a2_b2 + 2 * q_bytes);

    pmesg_mpz(msg_normal, "r", r);
    pmesg_mpz(msg_normal, "a2", a2);
    pmesg_mpz(msg_normal, "b2", b2);

    mpz_t a_1, b_1, h2_input_2;
    mpz_inits(a_1, b_1, h2_input_2, NULL);

    mpz_powm(a_1, reencrypted_ciphertext->A_1, a2, params->p);
    mpz_powm(b_1, reencrypted_ciphertext->B_1, b2, params->p);
    mpz_mul(h2_input_2, a_1, b_1);
    mpz_mod(h2_input_2, h2_input_2, params->p);

    uint8_t h2_output_2[anon_proxy_ske_key_size];
    memset(h2_output_2, 0, anon_proxy_ske_key_size);

    anon_proxy_h2(params, h2_input_2, h2_output_2);

    pmesg_hex(msg_normal, "K IN DEC()", anon_proxy_ske_key_size, h2_output_2);

    plaintext->m_size = reencrypted_ciphertext->D_size;
    plaintext->m = malloc(plaintext->m_size);
    memset(plaintext->m, 0, plaintext->m_size);

    struct anon_proxy_ske_ctx ctx2;
    uint8_t ctr2[anon_proxy_ske_block_size];
    memset(ctr2, 0, anon_proxy_ske_block_size);

    anon_proxy_ske_set_decrypt_key(&(ctx2), h2_output_2);

    anon_proxy_ske_block_decrypt(&(ctx2),
                                 (nettle_cipher_func *)anon_proxy_ske_decrypt,
                                 anon_proxy_ske_block_size,
                                 ctr2,
                                 reencrypted_ciphertext->D_size,
                                 plaintext->m,
                                 reencrypted_ciphertext->D);
    pmesg(msg_normal, "--------------------------------------------------");
    pmesg_hex(msg_normal, "plaintext", plaintext->m_size, plaintext->m);
}
