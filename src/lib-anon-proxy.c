#include <string.h>

#include "lib-anon-proxy.h"

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
    mpz_mod(output, output, params->q);

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
    mpz_mod(output, input, params->q);
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
    mpz_mod(output, output, params->q);

    if (mpz_cmp_ui(output, 0) == 0)
        mpz_set_ui(output, 1);
}

void anon_proxy_plaintext_clear(anon_proxy_plaintext_t plaintext)
{
    free(plaintext->m);
    plaintext->m = NULL;
    plaintext->m_size = 0;
}
void anon_proxy_ciphertext_clear(anon_proxy_ciphertext_t ciphertext)
{
    mpz_clears(ciphertext->A, ciphertext->B, ciphertext->C, ciphertext->S, NULL);

    free(ciphertext->D);
    ciphertext->D = NULL;
    ciphertext->D_size = 0;
}
void anon_proxy_reencrypted_ciphertext_clear(anon_proxy_reencrypted_ciphertext_t ciphertext)
{
    mpz_clears(ciphertext->A_1, ciphertext->B_1, ciphertext->U1, NULL);

    free(ciphertext->D);
    ciphertext->D = NULL;
    ciphertext->D_size = 0;

    free(ciphertext->U2);
    ciphertext->U2 = NULL;
    ciphertext->U2_size = 0;
}

void anon_proxy_pk_clear(anon_proxy_pk_t pk)
{
    mpz_clears(pk->pk1, pk->pk2, NULL);
    if (pk->use_pp)
    {
        mpz_pp_powm_clear(pk->pk1_pp);
        mpz_pp_powm_clear(pk->pk2_pp);
    }
}
void anon_proxy_sk_clear(anon_proxy_sk_t sk)
{
    mpz_clear(sk->sk);
}
void anon_proxy_rekey_clear(anon_proxy_rekey_t rekey)
{
    mpz_clears(rekey->rekey1[0], rekey->rekey1[1], rekey->rekey2_1, NULL);

    free(rekey->rekey2_2);
    rekey->rekey2_2 = NULL;
    rekey->rekey2_2_size = 0;
}
void anon_proxy_params_clear(anon_proxy_params_t params)
{
    mpz_clears(params->p, params->q, params->g, NULL);
    if (params->use_pp)
    {
        mpz_pp_powm_clear(params->g_pp);
    }
}
void anon_proxy_plaintext_init_manual(anon_proxy_plaintext_t plaintext, uint8_t *m, size_t m_size)
{
    plaintext->m = malloc(m_size);
    memcpy(plaintext->m, m, m_size);
    plaintext->m_size = m_size;
}
void anon_proxy_plaintext_init_random(gmp_randstate_t prng, anon_proxy_plaintext_t plaintext, size_t m_size)
{
    plaintext->m = malloc(m_size);
    size_t i;
    for (i = 0; i < m_size; i++)
        plaintext->m[i] = gmp_urandomm_ui(prng, 256);
    plaintext->m_size = m_size;
}

void anon_proxy_plaintext_print(FILE *file, anon_proxy_plaintext_t plaintext)
{
    size_t i;
    for (i = 0; i < plaintext->m_size; i++)
        fprintf(file, "%02x", plaintext->m[i]);
    fprintf(file, "\n");
};

void anon_proxy_ciphertext_print(FILE *file, anon_proxy_ciphertext_t ciphertext)
{
    fprintf(file, "(");
    mpz_out_str(file, 16, ciphertext->A);
    fprintf(file, ", ");
    mpz_out_str(file, 16, ciphertext->B);
    fprintf(file, ", ");
    mpz_out_str(file, 16, ciphertext->C);
    fprintf(file, ", ");
    size_t i;
    for (i = 0; i < ciphertext->D_size; i++)
        fprintf(file, "%02x", ciphertext->D[i]);
    fprintf(file, ", ");
    mpz_out_str(file, 16, ciphertext->S);
    fprintf(file, ")\n");
}

void anon_proxy_reencrypted_ciphertext_print(FILE *file, anon_proxy_reencrypted_ciphertext_t ciphertext)
{
    fprintf(file, "(");
    mpz_out_str(file, 16, ciphertext->A_1);
    fprintf(file, ", ");
    mpz_out_str(file, 16, ciphertext->B_1);
    fprintf(file, ", ");
    size_t i;
    for (i = 0; i < ciphertext->D_size; i++)
        fprintf(file, "%02x", ciphertext->D[i]);
    fprintf(file, ", ");
    mpz_out_str(file, 16, ciphertext->U1);
    fprintf(file, ", ");
    for (i = 0; i < ciphertext->U2_size; i++)
        fprintf(file, "%02x", ciphertext->U2[i]);
    fprintf(file, ")\n");
};

void anon_proxy_init(anon_proxy_params_t params,
                     gmp_randstate_t prng, anon_proxy_lambda lambda, bool use_pp)
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

    params->use_pp = use_pp;
    if (use_pp)
    {
        pmesg(msg_verbose, "Preprocessing enabled");
        mpz_pp_powm_init(params->g_pp, params->q_bits, params->g, params->p);
    }
    else
    {
        pmesg(msg_verbose, "Preprocessing disabled");
    }

    pmesg(msg_verbose, "Inizializzazione completata");
    pmesg_mpz(msg_very_verbose, "modulo", params->p);
    pmesg_mpz(msg_very_verbose, "ordine del sottogruppo", params->q);
    pmesg_mpz(msg_very_verbose, "generatore del sottogruppo", params->g);
}

void anon_proxy_h4_x_num(anon_proxy_params_t params, mpz_t x, uint8_t num, mpz_t output)
{
    size_t sk_size = mpz_sizeinbase(x, 256);
    uint8_t h4_num[sk_size + 1];
    mpz_export(h4_num, NULL, 1, 1, 0, 0, x);
    h4_num[sk_size] = num;
    anon_proxy_h4(params, h4_num, sk_size + 1, output);
}

void anon_proxy_keygen(anon_proxy_params_t params, gmp_randstate_t prng, bool use_pp, anon_proxy_sk_t sk, anon_proxy_pk_t pk)
{
    pmesg(msg_verbose, "Generazione chiavi");
    mpz_inits(sk->sk, pk->pk1, pk->pk2, NULL);

    pk->use_pp = use_pp;

    mpz_urandomm(sk->sk, prng, params->q);
    if (params->use_pp)
    {
        mpz_pp_powm(pk->pk1, sk->sk, params->g_pp);
    }
    else
    {
        mpz_powm(pk->pk1, params->g, sk->sk, params->p);
    }

    if (use_pp)
    {
        mpz_pp_powm_init(pk->pk1_pp, params->q_bits, pk->pk1, params->p);
    }

    mpz_t h4_0_out, h4_1_out;
    mpz_inits(h4_0_out, h4_1_out, NULL);
    anon_proxy_h4_x_num(params, sk->sk, 0, h4_0_out);
    anon_proxy_h4_x_num(params, sk->sk, 1, h4_1_out);

    mpz_mul(h4_1_out, sk->sk, h4_1_out);
    mpz_add(h4_0_out, h4_0_out, h4_1_out);

    mpz_mod(h4_0_out, h4_0_out, params->q);

    if (params->use_pp)
    {
        mpz_pp_powm(pk->pk2, h4_0_out, params->g_pp);
    }
    else
    {
        mpz_powm(pk->pk2, params->g, h4_0_out, params->p);
    }
    if (use_pp)
    {
        mpz_pp_powm_init(pk->pk2_pp, params->q_bits, pk->pk2, params->p);
    }

    pmesg(msg_verbose, "Generazione chiavi completata");
    pmesg_mpz(msg_very_verbose, "chiave privata", sk->sk);
    pmesg_mpz(msg_very_verbose, "chiave pubblica pk1", pk->pk1);
    pmesg_mpz(msg_very_verbose, "chiave pubblica pk2", pk->pk2);

    mpz_clears(h4_0_out, h4_1_out, NULL);
}

void anon_proxy_keygen_step1(mpz_t x, anon_proxy_params_t params, gmp_randstate_t prng, mpz_t num1, mpz_t num2, size_t h4_n)
{
    mpz_t h4_out;
    mpz_init(h4_out);
    anon_proxy_h4_x_num(params, x, h4_n, h4_out);

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

    pmesg_hex(msg_very_verbose, "r||a2||b2", *r_a2_b2_size, *r_a2_b2);
}

void anon_proxy_create_h3_ABCD(anon_proxy_params_t params, mpz_t A, mpz_t B, mpz_t C, uint8_t *D, size_t D_size, mpz_t output)
{

    size_t A_size = mpz_sizeinbase(A, 256);
    size_t B_size = mpz_sizeinbase(B, 256);
    size_t C_size = mpz_sizeinbase(C, 256);

    uint8_t h3_input[A_size + B_size + C_size + D_size];
    mpz_export(h3_input, NULL, 1, 1, 0, 0, A);
    mpz_export(h3_input + A_size, NULL, 1, 1, 0, 0, B);
    mpz_export(h3_input + A_size + B_size, NULL, 1, 1, 0, 0, C);
    memcpy(h3_input + A_size + B_size + C_size, D, D_size);

    mpz_t h3_input_mpz;
    mpz_init(h3_input_mpz);
    mpz_import(h3_input_mpz, A_size + B_size + C_size + D_size, 1, 1, 0, 0, h3_input);

    anon_proxy_h3(params, h3_input_mpz, output);

    mpz_clear(h3_input_mpz);
}

void anon_proxy_rekeygen(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_sk_t sk, anon_proxy_pk_t pk, anon_proxy_rekey_t rekey)
{
    pmesg(msg_verbose, "Inizializzazione rekeygen");

    mpz_t a1, a2, b1, b2;
    mpz_inits(a1, a2, b1, b2, NULL);

    anon_proxy_keygen_step1(sk->sk, params, prng, a1, a2, 0);
    anon_proxy_keygen_step1(sk->sk, params, prng, b1, b2, 1);

    mpz_init_set(rekey->rekey1[0], a1);
    mpz_init_set(rekey->rekey1[1], b1);

    pmesg_mpz(msg_very_verbose, "a1", rekey->rekey1[0]);
    pmesg_mpz(msg_very_verbose, "b1", rekey->rekey1[1]);

    pmesg_mpz(msg_very_verbose, "a2", a2);
    pmesg_mpz(msg_very_verbose, "b2", b2);

    // random r
    mpz_t r;
    mpz_init(r);
    do
    {
        mpz_urandomm(r, prng, params->q);
    } while (mpz_sizeinbase(r, 2) != params->q_bits || mpz_cmp_ui(r, 0) == 0);

    pmesg_mpz(msg_very_verbose, "r", r);

    uint8_t *r_a2_b2 = NULL;
    size_t r_a2_b2_size = 0;

    anon_proxy_create_r_a2_b2(params, r, a2, b2, &r_a2_b2, &r_a2_b2_size);
    mpz_clear(r);

    // H1(r||a2||b2)
    mpz_t h1_output;
    mpz_init(h1_output);
    pmesg_hex(msg_very_verbose, "r||a2||b2", r_a2_b2_size, r_a2_b2);

    anon_proxy_h1(params, r_a2_b2, r_a2_b2_size, h1_output);

    //  rk2 = (g^h1, ...)
    if (params->use_pp)
        mpz_pp_powm(rekey->rekey2_1, h1_output, params->g_pp);
    else
        mpz_powm(rekey->rekey2_1, params->g, h1_output, params->p);

    // pk1^H1_output
    mpz_t h2_input;
    mpz_init(h2_input);
    if (pk->use_pp)
        mpz_pp_powm(h2_input, h1_output, pk->pk1_pp);
    else
        mpz_powm(h2_input, pk->pk1, h1_output, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    memset(h2_output, 0, anon_proxy_ske_key_size);
    anon_proxy_h2(params, h2_input, h2_output);

    mpz_clears(h1_output, h2_input, NULL);

    rekey->rekey2_2_size = r_a2_b2_size;
    rekey->rekey2_2 = malloc(rekey->rekey2_2_size);
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

    pmesg_mpz(msg_very_verbose, "rk2_1 (U1)", rekey->rekey2_1);
    pmesg_hex(msg_very_verbose, "rk2_2 (U2)", rekey->rekey2_2_size, rekey->rekey2_2);

    free(r_a2_b2);
    mpz_clears(a1, a2, b1, b2, NULL);
}

void anon_proxy_encrypt(anon_proxy_params_t params, gmp_randstate_t prng, anon_proxy_pk_t pk, anon_proxy_plaintext_t plaintext, anon_proxy_ciphertext_t ciphertext)
{
    pmesg(msg_verbose, "Inizio cifratura");
    mpz_t r, r_1;
    mpz_inits(r, r_1, NULL);
    do
    {
        mpz_urandomm(r, prng, params->q);
        mpz_urandomm(r_1, prng, params->q);
    } while (mpz_cmp(r, r_1) == 0 || mpz_cmp_ui(r, 0) == 0 || mpz_cmp_ui(r_1, 0) == 0);

    pmesg_mpz(msg_very_verbose, "r", r);
    pmesg_mpz(msg_very_verbose, "r_1", r_1);

    mpz_inits(ciphertext->A, ciphertext->B, ciphertext->C, ciphertext->S, NULL);

    if (params->use_pp)
    {
        mpz_pp_powm(ciphertext->A, r, params->g_pp);
        mpz_pp_powm(ciphertext->C, r_1, params->g_pp);
    }
    else
    {
        mpz_powm(ciphertext->A, params->g, r, params->p);
        mpz_powm(ciphertext->C, params->g, r_1, params->p);
    }

    if (pk->use_pp)
        mpz_pp_powm(ciphertext->B, r, pk->pk1_pp);
    else
        mpz_powm(ciphertext->B, pk->pk1, r, params->p);

    pmesg_mpz(msg_very_verbose, "A", ciphertext->A);
    pmesg_mpz(msg_very_verbose, "B", ciphertext->B);
    pmesg_mpz(msg_very_verbose, "C", ciphertext->C);

    mpz_t h2_input;
    mpz_init(h2_input);
    if (pk->use_pp)
        mpz_pp_powm(h2_input, r, pk->pk2_pp);
    else
        mpz_powm(h2_input, pk->pk2, r, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];

    anon_proxy_h2(params, h2_input, h2_output);

    mpz_clear(h2_input);

    pmesg_hex(msg_very_verbose, "k in encrypt", anon_proxy_ske_key_size, h2_output);

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

    pmesg_hex(msg_very_verbose, "D", ciphertext->D_size, ciphertext->D);

    anon_proxy_create_h3_ABCD(params, ciphertext->A, ciphertext->B, ciphertext->C, ciphertext->D, ciphertext->D_size, ciphertext->S);

    mpz_mul(ciphertext->S, ciphertext->S, r);
    mpz_add(ciphertext->S, ciphertext->S, r_1);
    mpz_mod(ciphertext->S, ciphertext->S, params->q);

    pmesg_mpz(msg_very_verbose, "S", ciphertext->S);

    pmesg(msg_verbose, "Fine cifratura");
    mpz_clears(r, r_1, NULL);
}

void anon_proxy_decrypt_original(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_ciphertext_t ciphertext, anon_proxy_plaintext_t plaintext)
{
    pmesg(msg_verbose, "Inizio decifratura messaggio originale");

    mpz_t left_check;
    mpz_init(left_check);
    if (params->use_pp)
        mpz_pp_powm(left_check, ciphertext->S, params->g_pp);
    else
        mpz_powm(left_check, params->g, ciphertext->S, params->p);

    mpz_t right_check;
    mpz_init(right_check);
    anon_proxy_create_h3_ABCD(params, ciphertext->A, ciphertext->B, ciphertext->C, ciphertext->D, ciphertext->D_size, right_check);
    mpz_powm(right_check, ciphertext->A, right_check, params->p);
    mpz_mul(right_check, right_check, ciphertext->C);
    mpz_mod(right_check, right_check, params->p);

    assert(mpz_cmp(right_check, left_check) == 0);
    pmesg(msg_very_verbose, "right_check == left_check");
    mpz_clears(left_check, right_check, NULL);

    mpz_t h4_0, h4_1;
    mpz_inits(h4_0, h4_1, NULL);

    anon_proxy_h4_x_num(params, sk->sk, 0, h4_0);
    anon_proxy_h4_x_num(params, sk->sk, 1, h4_1);

    mpz_t a_pow, b_pow, h2_input;
    mpz_inits(a_pow, b_pow, h2_input, NULL);
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

    pmesg_hex(msg_very_verbose, "decrypted", plaintext->m_size, plaintext->m);
    pmesg(msg_verbose, "Fine decifratura messaggio originale");
}

void anon_proxy_reencrypt(anon_proxy_params_t params, anon_proxy_rekey_t rekey, anon_proxy_ciphertext_t ciphertext, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext)
{
    pmesg(msg_verbose, "Inizio recifratura");

    mpz_t right_check;
    mpz_init(right_check);
    anon_proxy_create_h3_ABCD(params, ciphertext->A, ciphertext->B, ciphertext->C, ciphertext->D, ciphertext->D_size, right_check);
    mpz_powm(right_check, ciphertext->A, right_check, params->p);
    mpz_mul(right_check, right_check, ciphertext->C);
    mpz_mod(right_check, right_check, params->p);

    mpz_t left_check;
    mpz_init(left_check);
    if (params->use_pp)
        mpz_pp_powm(left_check, ciphertext->S, params->g_pp);
    else
        mpz_powm(left_check, params->g, ciphertext->S, params->p);

    assert(mpz_cmp(right_check, left_check) == 0);

    mpz_clears(left_check, right_check, NULL);

    mpz_inits(reencrypted_ciphertext->A_1, reencrypted_ciphertext->B_1, NULL);
    mpz_powm(reencrypted_ciphertext->A_1, ciphertext->A, rekey->rekey1[0], params->p);
    mpz_powm(reencrypted_ciphertext->B_1, ciphertext->B, rekey->rekey1[1], params->p);

    reencrypted_ciphertext->D_size = ciphertext->D_size;
    reencrypted_ciphertext->D = malloc(reencrypted_ciphertext->D_size);
    memcpy(reencrypted_ciphertext->D, ciphertext->D, reencrypted_ciphertext->D_size);

    mpz_init_set(reencrypted_ciphertext->U1, rekey->rekey2_1);

    reencrypted_ciphertext->U2_size = rekey->rekey2_2_size;
    reencrypted_ciphertext->U2 = malloc(reencrypted_ciphertext->U2_size);
    memcpy(reencrypted_ciphertext->U2, rekey->rekey2_2, reencrypted_ciphertext->U2_size);

    pmesg_mpz(msg_very_verbose, "A_1", reencrypted_ciphertext->A_1);
    pmesg_mpz(msg_very_verbose, "B_1", reencrypted_ciphertext->B_1);
    pmesg_hex(msg_very_verbose, "D", reencrypted_ciphertext->D_size, reencrypted_ciphertext->D);
    pmesg_mpz(msg_very_verbose, "U1", reencrypted_ciphertext->U1);
    pmesg_hex(msg_very_verbose, "U2", reencrypted_ciphertext->U2_size, reencrypted_ciphertext->U2);
    pmesg(msg_verbose, "Fine recifratura");
}

void anon_proxy_decrypt_reencrypted(anon_proxy_params_t params, anon_proxy_sk_t sk, anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext, anon_proxy_plaintext_t plaintext)
{
    pmesg(msg_verbose, "Inizio decifratura messaggio recifrato");
    mpz_t h2_input;
    mpz_init(h2_input);
    mpz_powm(h2_input, reencrypted_ciphertext->U1, sk->sk, params->p);

    uint8_t h2_output[anon_proxy_ske_key_size];
    memset(h2_output, 0, anon_proxy_ske_key_size);
    anon_proxy_h2(params, h2_input, h2_output);
    mpz_clear(h2_input);

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

    mpz_t left_check, left_check_2;
    mpz_inits(left_check, left_check_2, NULL);

    anon_proxy_h1(params, r_a2_b2, reencrypted_ciphertext->U2_size, left_check);

    if (params->use_pp)
        mpz_pp_powm(left_check_2, left_check, params->g_pp);
    else
        mpz_powm(left_check_2, params->g, left_check, params->p);

    assert(mpz_cmp(left_check_2, reencrypted_ciphertext->U1) == 0);

    mpz_clears(left_check, left_check_2, NULL);

    pmesg_hex(msg_very_verbose, "r_a2_b2", reencrypted_ciphertext->U2_size, r_a2_b2);

    size_t q_bytes = params->q_bits / 8;
    mpz_t r, a2, b2;

    mpz_inits(r, a2, b2, NULL);

    mpz_import(r, q_bytes, 1, 1, 0, 0, r_a2_b2);
    mpz_import(a2, q_bytes, 1, 1, 0, 0, r_a2_b2 + q_bytes);
    mpz_import(b2, q_bytes, 1, 1, 0, 0, r_a2_b2 + 2 * q_bytes);

    pmesg_mpz(msg_very_verbose, "r", r);
    pmesg_mpz(msg_very_verbose, "a2", a2);
    pmesg_mpz(msg_very_verbose, "b2", b2);

    mpz_t a_1, b_1, h2_input_2;
    mpz_inits(a_1, b_1, h2_input_2, NULL);

    mpz_powm(a_1, reencrypted_ciphertext->A_1, a2, params->p);
    mpz_powm(b_1, reencrypted_ciphertext->B_1, b2, params->p);
    mpz_mul(h2_input_2, a_1, b_1);
    mpz_mod(h2_input_2, h2_input_2, params->p);

    mpz_clears(a_1, b_1, r, a2, b2, NULL);

    uint8_t h2_output_2[anon_proxy_ske_key_size];
    memset(h2_output_2, 0, anon_proxy_ske_key_size);

    anon_proxy_h2(params, h2_input_2, h2_output_2);
    mpz_clear(h2_input_2);

    pmesg_hex(msg_very_verbose, "K IN DEC()", anon_proxy_ske_key_size, h2_output_2);

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
    pmesg_hex(msg_very_verbose, "plaintext", plaintext->m_size, plaintext->m);
    pmesg(msg_verbose, "Fine decifratura messaggio recifrato");
}
