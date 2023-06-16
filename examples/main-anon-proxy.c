#include "lib-anon-proxy.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_normal);
    anon_proxy_params_t params;
    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 32);

    printf("\n--------INIT--------\n");
    anon_proxy_init(params, prng, anon_proxy_lambda_80);

    printf("\n--------KEYGEN--------\n");
    anon_proxy_sk_t sk_1;
    anon_proxy_pk_t pk_1;

    anon_proxy_keygen(params, prng, sk_1, pk_1);

    printf("\n--------PLAINTEXT--------\n");
    anon_proxy_plaintext_t plaintext;
    anon_proxy_plaintext_init_random(prng, plaintext, 16);
    anon_proxy_plaintext_print(stdout, plaintext);

    printf("\n--------ENCRYPT--------\n");
    anon_proxy_ciphertext_t ciphertext;
    anon_proxy_encrypt(params, prng, pk_1, plaintext, ciphertext);
    anon_proxy_ciphertext_print(stdout, ciphertext);

    printf("\n--------DECRYPT--------\n");
    anon_proxy_plaintext_t plaintext2;
    anon_proxy_decrypt_original(params, sk_1, ciphertext, plaintext2);
    anon_proxy_plaintext_print(stdout, plaintext2);

    assert(plaintext->m_size == plaintext2->m_size);
    assert(memcmp(plaintext->m, plaintext2->m, plaintext->m_size) == 0);

    printf("\n--------KEYGEN2-------\n");
    anon_proxy_sk_t sk_2;
    anon_proxy_pk_t pk_2;
    anon_proxy_keygen(params, prng, sk_2, pk_2);

    printf("\n--------REKEYGEN-------\n");
    anon_proxy_rekey_t rekey;
    anon_proxy_rekeygen(params, prng, sk_1, pk_2, rekey);

    printf("\n--------REENCRYPT-------\n");
    anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext;
    anon_proxy_reencrypt(params, rekey, ciphertext, reencrypted_ciphertext);
    anon_proxy_reencrypted_ciphertext_print(stdout, reencrypted_ciphertext);

    printf("\n--------DECRYPT2-------\n");
    anon_proxy_plaintext_t plaintext3;
    anon_proxy_decrypt_reencrypted(params, sk_2, reencrypted_ciphertext, plaintext3);
    anon_proxy_plaintext_print(stdout, plaintext3);

    assert(plaintext->m_size == plaintext3->m_size);
    assert(memcmp(plaintext->m, plaintext3->m, plaintext->m_size) == 0);

    printf("\n--------CLEAR-------\n");

    anon_proxy_plaintext_clear(plaintext);
    anon_proxy_plaintext_clear(plaintext2);
    anon_proxy_plaintext_clear(plaintext3);
    anon_proxy_ciphertext_clear(ciphertext);
    anon_proxy_reencrypted_ciphertext_clear(reencrypted_ciphertext);
    anon_proxy_rekey_clear(rekey);
    anon_proxy_sk_clear(sk_1);
    anon_proxy_sk_clear(sk_2);
    anon_proxy_pk_clear(pk_1);
    anon_proxy_pk_clear(pk_2);
    anon_proxy_params_clear(params);
    gmp_randclear(prng);

    printf("Tutto ok\n");
    return 0;
}