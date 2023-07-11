#include <time.h>
#include <stdlib.h>

#include "lib-elgamal-mod.h"
#include "lib-misc.h"
#include "lib-mesg.h"

int main()
{
    set_messaging_level(msg_normal);
    srand(time(NULL));

    gmp_randstate_t prng;
    gmp_randinit_default(prng);
    gmp_randseed_os_rng(prng, 256);

    elgamal_mod_params_t params;
    elgamal_mod_init(params, 80, prng, false);

    elgamal_plaintext_t plaintext;
    elgamal_mod_plaintext_init_random(plaintext, prng, 32);

    printf("\n--------PLAINTEXT--------\n");
    elgamal_mod_plaintext_print(stdout, plaintext);

    elgamal_ciphertext_t ciphertext;
    printf("\n--------ENCRYPT--------\n");
    elgamal_mod_encrypt(params, prng, plaintext, ciphertext);

    elgamal_mod_ciphertext_print(stdout, ciphertext);

    elgamal_mod_plaintext_clear(plaintext);

    printf("\n--------DECRYPT--------\n");
    elgamal_mod_decrypt(params, ciphertext, plaintext);

    elgamal_mod_plaintext_print(stdout, plaintext);

    elgamal_mod_ciphertext_clear(ciphertext);
    elgamal_mod_plaintext_clear(plaintext);
    elgamal_mod_params_clear(params);
    gmp_randclear(prng);
}