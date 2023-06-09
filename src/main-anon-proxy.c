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

    anon_proxy_sk_t sk_1;
    anon_proxy_pk_t pk_1;

    anon_proxy_keygen(params, prng, sk_1, pk_1);

    anon_proxy_plaintext_t plaintext;
    plaintext->m_size = 16;
    plaintext->m = malloc(plaintext->m_size);
    memset(plaintext->m, 0, plaintext->m_size);

    size_t i = 0;
    for (i = 0; i < plaintext->m_size; i++)
    {
        plaintext->m[i] = i % 256;
    }

    pmesg_hex(msg_normal, "plaintext", plaintext->m_size, plaintext->m);
    anon_proxy_ciphertext_t ciphertext;

    anon_proxy_encrypt(params, prng, pk_1, plaintext, ciphertext);

    anon_proxy_plaintext_t plaintext2;
    anon_proxy_decrypt_original(params, sk_1, ciphertext, plaintext2);

    assert(plaintext->m_size == plaintext2->m_size);
    assert(memcmp(plaintext->m, plaintext2->m, plaintext->m_size) == 0);

    pmesg(msg_verbose, "--------------------------------------------------");
    pmesg(msg_verbose, "          Encryption and decryption: OK!          ");
    pmesg(msg_verbose, "--------------------------------------------------");

    anon_proxy_sk_t sk_2;
    anon_proxy_pk_t pk_2;
    anon_proxy_keygen(params, prng, sk_2, pk_2);

    anon_proxy_rekey_t rekey;
    anon_proxy_rekeygen(params, prng, sk_1, pk_2, rekey);
    anon_proxy_reencrypted_ciphertext_t reencrypted_ciphertext;

    anon_proxy_reencrypt(params, rekey, ciphertext, reencrypted_ciphertext);

    anon_proxy_plaintext_t plaintext3;

    pmesg(msg_normal, "--------------------------------------------------");

    anon_proxy_decrypt_reencrypted(params, sk_2, reencrypted_ciphertext, plaintext3);
    assert(plaintext->m_size == plaintext3->m_size);
    assert(memcmp(plaintext->m, plaintext3->m, plaintext->m_size) == 0);
    pmesg(msg_verbose, "--------------------------------------------------");
    pmesg(msg_verbose, "         Reencryption and redecryption: OK!       ");
    pmesg(msg_verbose, "--------------------------------------------------");
    return 0;
}