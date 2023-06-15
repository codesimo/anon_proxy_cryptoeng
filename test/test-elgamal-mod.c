/*
 * esperimenti da eseguire:
 * - test-elgamal-mod verbose
 * - test-elgamal-mod bench
 */

#include "lib-elgamal-mod.h"
#include "lib-mesg.h"
#include "lib-misc.h"
#include "lib-timing.h"

#define prng_sec_level 128
#define default_message_bytes 32
#define default_lambda elgamal_mod_lambda_128

#define bench_sampling_time 5 /* secondi */
#define max_samples (bench_sampling_time * 1000)

int main(int argc, char *argv[])
{
    gmp_randstate_t prng;
    elgamal_mod_params_t params;
    elgamal_plaintext_t msg, msg2;
    elgamal_ciphertext_t enc;
    char *fixed_msg = NULL; /* default: messaggio causale */
    size_t fixed_msg_len = 0;
    bool do_bench = false;
    bool is_verbose = false;
    stats_t timing;
    elapsed_time_t time;
    long int applied_sampling_time = 0;
    elgamal_mod_lambda lambda = default_lambda;
    int exit_status = 0;
    long prng_seed = -1; /* -1 = seed casuale sicuro */

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "verbose") == 0)
        {
            set_messaging_level(msg_very_verbose);
            is_verbose = true;
        }
        else if (strcmp(argv[i], "quiet") == 0)
            set_messaging_level(msg_silence);
        else if (strcmp(argv[i], "bench") == 0)
        {
            applied_sampling_time = bench_sampling_time;
            do_bench = true;
        }
        else if (strcmp(argv[i], "lambda") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            lambda = atoi(argv[i + 1]);
            if (lambda != elgamal_mod_lambda_112 && lambda != elgamal_mod_lambda_128 && lambda != elgamal_mod_lambda_80)
            {
                printf("lambda non valido!\n");
                exit(1);
            }
            i++;
        }
        else if (strcmp(argv[i], "seed") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            prng_seed = atol(argv[i + 1]);
            if (prng_seed < 0)
            {
                printf("seed non valido!\n");
                exit(1);
            }
            i++;
        }
        else if (strcmp(argv[i], "message") == 0)
        {
            if (i + 1 >= argc)
            {
                printf("argomento mancante!\n");
                exit(1);
            }
            assert(argv[i + 1]);
            fixed_msg = argv[i + 1];
            fixed_msg_len = strlen(fixed_msg);
            if (fixed_msg_len % 16 != 0)
            {
                printf("lunghezza del messaggio non valida. Il messaggio deve essere %%16\n");
                exit(1);
            }
            i++;
        }
        else
        {
            printf("utilizzo: %s [verbose|quiet] "
                   "[lambda 80|112|128] [seed <n>] [message <n>] [bench]\n",
                   argv[0]);
            exit(1);
        }
    }
    if (do_bench)
        set_messaging_level(msg_silence);

    printf("Calibrazione strumenti per il timing...\n");
    calibrate_timing_methods();

    printf("\nInizializzazione PRNG ");
    gmp_randinit_default(prng);
    if (prng_seed >= 0)
    {
        printf("(modalità deterministica: seme = %ld)...\n", prng_seed);
        gmp_randseed_ui(prng, (unsigned long int)prng_seed);
    }
    else
    {
        printf("(modalità sicura)...\n");
        gmp_randseed_os_rng(prng, prng_sec_level);
    }

    printf("\nLambda: %d\n", lambda);

    printf("\nGenerazione parametri Elgamal-mod\n");
    perform_oneshot_cpu_time_sampling(time, tu_sec, {
        elgamal_mod_init(params, lambda, prng);
    });
    if (do_bench)
        printf_et(" elgamal_mod_init: ", time, tu_sec, "\n");

    if (fixed_msg != NULL)
    {
        printf("\nMessaggio fissato...");
        elgamal_mod_plaintext_init_manual(msg, (unsigned char *)fixed_msg, fixed_msg_len);
        if (is_verbose)
        {
            printf("\nMessaggio fissato: ");
            elgamal_mod_plaintext_print(stdout, msg);
        }
    }
    else
    {
        printf("\nGenerazione messaggio casuale...\n");
        elgamal_mod_plaintext_init_random(msg, prng, default_message_bytes);
        if (is_verbose)
        {
            printf("Messaggio casuale: ");
            elgamal_mod_plaintext_print(stdout, msg);
        }
    }

    printf("\nCifratura...\n");
    perform_wc_time_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,
        {
            elgamal_mod_encrypt(params, prng, msg, enc);
            elgamal_mod_ciphertext_clear(enc);
        },
        {});
    if (do_bench)
        printf_short_stats(" elgamal_mod_encrypt", timing, "");

    elgamal_mod_encrypt(params, prng, msg, enc);
    if (is_verbose)
    {
        printf("Cifratura: ");
        elgamal_mod_ciphertext_print(stdout, enc);
    }

    printf("\nDecifratura...\n");
    perform_wc_time_sampling_period(
        timing, applied_sampling_time, max_samples, tu_millis,
        {
            elgamal_mod_decrypt(params, enc, msg2);
            elgamal_mod_plaintext_clear(msg2);
        },
        {});
    if (do_bench)
        printf_short_stats(" elgamal_decrypt", timing, "");

    elgamal_mod_decrypt(params, enc, msg2);
    if (is_verbose)
    {
        printf("Decifratura: ");
        elgamal_mod_plaintext_print(stdout, msg2);
    }

    if (msg->m_size != msg2->m_size || memcmp(msg->m, msg2->m, msg->m_size) != 0)
    {
        printf("Sembra che il processo di decifratura non abbia restituito il "
               "messaggio originale!\n");
        exit_status = 1;
    }
    else
        printf("Tutto ok!\n");

    elgamal_mod_plaintext_clear(msg);
    elgamal_mod_plaintext_clear(msg2);
    elgamal_mod_ciphertext_clear(enc);
    gmp_randclear(prng);
    exit(exit_status);
}
