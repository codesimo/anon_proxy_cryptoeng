#include <time.h>
#include <stdlib.h>

#include "elgamal-mod.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_verbose);
    srand(time(NULL));

    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 256);

    elgamal_mod_params_t params;
    elgamal_mod_init(params, 80, prng);

    elgamal_plaintext_t plaintext;
    plaintext->m_size = 32;
    plaintext->m = (uint8_t *)malloc(plaintext->m_size * sizeof(uint8_t));
    for (size_t i = 0; i < plaintext->m_size; i++)
        plaintext->m[i] = rand() % 256;
    

    pmesg(msg_verbose,"\n--------PLAINTEXT--------\n");
    pmesg_hex(msg_verbose, "plaintext", plaintext->m_size, plaintext->m);

    elgamal_ciphertext_t ciphertext;
    pmesg(msg_verbose,"\n--------ENCRYPT--------\n");
    elgamal_mod_encrypt(params, prng, plaintext, ciphertext);

    elgamal_plaintext_t plaintext2;
    pmesg(msg_verbose,"\n--------DECRYPT--------\n");
    elgamal_mod_decrypt(params, ciphertext, plaintext2);
}