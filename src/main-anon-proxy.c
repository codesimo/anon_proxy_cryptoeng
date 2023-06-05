#include "anon-proxy.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_very_verbose);
    anon_proxy_params_t params;
    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 32);
    anon_proxy_init(params, prng, anon_proxy_lambda_80);

    anon_proxy_sk_t sk;
    anon_proxy_pk_t pk;

    anon_proxy_keygen(params, prng, sk, pk);

    anon_proxy_plaintext_t plaintext;
    plaintext->m_size = 20;
    plaintext->m = malloc(plaintext->m_size);
    memset(plaintext->m, 0, plaintext->m_size);
    for (size_t i = 0; i < plaintext->m_size; i++)
    {
        plaintext->m[i] = rand() % 256;
    }
    pmesg_hex(msg_verbose, "plaintext", plaintext->m_size, plaintext->m);
    anon_proxy_ciphertext_t ciphertext;

    anon_proxy_encrypt(params, prng, pk, plaintext, ciphertext);

    anon_proxy_plaintext_t plaintext2;
    anon_proxy_decrypt_original(params, sk, ciphertext, plaintext2);

    assert(plaintext->m_size == plaintext2->m_size);
    assert(memcmp(plaintext->m, plaintext2->m, plaintext->m_size) == 0);

    pmesg(msg_verbose, "----------Encryption and decryption: OK!----------");

    anon_proxy_rekey_t rekey;
    anon_proxy_rekeygen(params, prng, sk, pk, rekey);

    anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext;

    anon_proxy_reencrypt(params, rekey, ciphertext, reencrypted_ciphertext);
    anon_proxy_plaintext_t plaintext3;

    anon_proxy_decrypt_reencrypted(params, sk, reencrypted_ciphertext, plaintext3);

    return 0;
}