/*
 *  Copyright 2016 Mario Di Raimondo <diraimondo@dmi.unict.it>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * libreria per le esponenziazioni modulari con e senza precomputazione: S-a-M,
 * a finestra fissa (a rango k) e a finestra variabile (a sliding window)
 */

#include "lib-powm.h"

/* square-and-multiply di base nella variante "da sinistra a destra"
 * (per comparazione - da non usare in produzione) */
void mpz_naive_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                    const mpz_t mod) {
    mpz_t exp2;
    size_t exp_bits;

    assert(res);
    assert(base);
    assert(exp);
    assert(mod);
    assert(res != base && res != exp && res != mod);

    if (mpz_cmp_ui(exp, 0) == 0) {
        mpz_set_ui(res, 1);
        return;
    }

    mpz_init(exp2);
    mpz_abs(exp2, exp);
    exp_bits = mpz_sizeinbase(exp2, 2);
    assert(exp_bits >= 1);
    assert(mpz_tstbit(exp2, exp_bits - 1));

    mpz_set(res, base);
    for (long i = exp_bits - 2; i >= 0; i--) {
        mpz_mul(res, res, res);
        mpz_mod(res, res, mod);
        if (mpz_tstbit(exp2, i)) {
            mpz_mul(res, res, base);
            mpz_mod(res, res, mod);
        }
    }

    if (mpz_sgn(exp) == -1) {
        if (!mpz_invert(res, res, mod))
            mpz_set_ui(res, 0L);
    }
    mpz_clear(exp2);
}

/* esponenziazione modulare a finestra fissa (a rango k) */
void mpz_window_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                     const mpz_t mod, size_t window_size) {
    mpz_t exp2, t;
    size_t exp_bits, exp_b_digits, window_base;

    assert(res);
    assert(base);
    assert(exp);
    assert(mod);
    assert(res != base && res != exp && res != mod);
    assert(window_size > 0);

    if (mpz_cmp_ui(exp, 0) == 0) {
        mpz_set_ui(res, 1);
        return;
    }

    mpz_init(t);
    mpz_init(exp2);
    mpz_abs(exp2, exp);
    exp_bits = mpz_sizeinbase(exp2, 2);
    assert(exp_bits >= 1);
    assert(mpz_tstbit(exp2, exp_bits - 1));

    window_base = 1 << window_size;

    mpz_t table[window_base];
    for (size_t i = 0; i < window_base; i++)
        if (i % 2 || i == 0 || i == 2)
            mpz_init(table[i]);

    mpz_set_ui(table[0], 1);
    mpz_set(table[1], base);
    mpz_mul(table[2], base, base);
    mpz_mod(table[2], table[2], mod);
    for (size_t i = 1; i < window_base / 2; i++) {
        mpz_mul(table[2 * i + 1], table[2 * i - 1], table[2]);
        mpz_mod(table[2 * i + 1], table[2 * i + 1], mod);
    }
    mpz_clear(table[2]);

    exp_b_digits = (size_t)ceilf((float)exp_bits / (float)window_size);
    unsigned long exp_in_base_b[exp_b_digits];
    for (size_t i = 0; i < exp_b_digits; i++) {
        mpz_tdiv_r_2exp(t, exp2, window_size);
        mpz_tdiv_q_2exp(exp2, exp2, window_size);
        exp_in_base_b[i] = mpz_get_ui(t);
        assert(exp_in_base_b[i] >= 0);
        assert(exp_in_base_b[i] < window_base);
    }

    mpz_set_ui(t, 1);
    mpz_set_ui(res, 1);
    for (long j = exp_b_digits - 1; j >= 0; j--) {
        unsigned long u = exp_in_base_b[j];
        unsigned long low_zeros = 0;
        while (u != 0 && u % 2 == 0) {
            low_zeros++;
            u >>= 1;
        }
        mpz_powm_ui(res, res, 1 << (window_size - low_zeros), mod);
        mpz_mul(res, res, table[u]);
        mpz_mod(res, res, mod);
        mpz_powm_ui(res, res, 1 << (low_zeros), mod);
    }

    if (mpz_sgn(exp) == -1) {
        if (!mpz_invert(res, res, mod))
            mpz_set_ui(res, 0L);
    }

    for (size_t i = 0; i < window_base; i++)
        if (i % 2 || i == 0)
            mpz_clear(table[i]);
    mpz_clears(exp2, t, NULL);
}

/* esponenziazione modulare a finestra variabile (sliding window) */
void mpz_swindow_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                      const mpz_t mod, size_t max_window_size) {
    mpz_t exp2;
    size_t exp_bits, window_base;

    assert(res);
    assert(base);
    assert(exp);
    assert(mod);
    assert(res != base && res != exp && res != mod);
    assert(max_window_size > 0);

    if (mpz_cmp_ui(exp, 0) == 0) {
        mpz_set_ui(res, 1);
        return;
    }

    mpz_init(exp2);
    mpz_abs(exp2, exp);
    exp_bits = mpz_sizeinbase(exp2, 2);
    assert(exp_bits >= 1);
    assert(mpz_tstbit(exp2, exp_bits - 1));

    window_base = 1 << max_window_size;

    mpz_t table[window_base];
    for (size_t i = 0; i < window_base; i++)
        if (i % 2 || i == 0 || i == 2)
            mpz_init(table[i]);

    mpz_set_ui(table[0], 1);
    mpz_set(table[1], base);
    mpz_mul(table[2], base, base);
    mpz_mod(table[2], table[2], mod);
    for (size_t i = 1; i < window_base / 2; i++) {
        mpz_mul(table[2 * i + 1], table[2 * i - 1], table[2]);
        mpz_mod(table[2 * i + 1], table[2 * i + 1], mod);
    }
    mpz_clear(table[2]);

    mpz_set_ui(res, 1);
    for (long i = exp_bits - 1; i >= 0;) {
        if (mpz_tstbit(exp2, i) == 0) {
            mpz_mul(res, res, res);
            mpz_mod(res, res, mod);
            i--;
        } else {
            long j =
                (i - (long)max_window_size + 1 >= 0 ? i - max_window_size + 1
                                                    : 0);
            while (mpz_tstbit(exp2, j) == 0)
                j++;
            assert(i >= j);
            assert((i - j + 1) >= 1);
            assert((size_t)(i - j + 1) <= max_window_size);
            long win_val = mpz_tstbit(exp2, i);
            for (long k = i - 1; k >= j; k--) {
                win_val <<= 1;
                win_val |= mpz_tstbit(exp2, k);
            }
            assert(win_val % 2);
            mpz_powm_ui(res, res, 1 << (i - j + 1), mod);
            mpz_mul(res, res, table[win_val]);
            mpz_mod(res, res, mod);
            i = j - 1;
        }
    }

    if (mpz_sgn(exp) == -1) {
        if (!mpz_invert(res, res, mod))
            mpz_set_ui(res, 0L);
    }

    for (size_t i = 0; i < window_base; i++)
        if (i % 2 || i == 0)
            mpz_clear(table[i]);
    mpz_clear(exp2);
}

/* precomputazione relativa all'esponenziazione modulare elementare tramite
 * 'mpz_pp_powm' */
void mpz_pp_powm_init(mpz_pp_powm_t pp, size_t exp_bits, const mpz_t base,
                      const mpz_t mod) {
    assert(pp);
    assert(exp_bits > 0);
    assert(base);
    assert(mod);

    pp->table = (mpz_t *)malloc(sizeof(mpz_t) * exp_bits);
    assert(pp->table);
    pp->exp_bits = exp_bits;

    mpz_init_set(pp->mod, mod);

    for (size_t i = 0; i < pp->exp_bits; i++)
        mpz_init(pp->table[i]);

    mpz_set(pp->table[0], base);
    for (size_t i = 1; i < exp_bits; i++) {
        mpz_mul(pp->table[i], pp->table[i - 1], pp->table[i - 1]);
        mpz_mod(pp->table[i], pp->table[i], mod);
    }
}

/* esponenziazione modulare elementare (S-a-M) con precomputazione */
void mpz_pp_powm(mpz_t res, const mpz_t exp, const mpz_pp_powm_t pp) {
    mpz_t exp2;
    size_t exp_bits;

    assert(res);
    assert(exp);
    assert(res != exp);
    assert(pp);

    if (mpz_cmp_ui(exp, 0) == 0) {
        mpz_set_ui(res, 1);
        return;
    }

    mpz_init(exp2);
    mpz_abs(exp2, exp);
    exp_bits = mpz_sizeinbase(exp2, 2);

    assert(exp_bits <= pp->exp_bits);
    assert(exp_bits >= 1);
    assert(mpz_tstbit(exp2, exp_bits - 1));

    mpz_set(res, pp->table[exp_bits - 1]);
    for (long i = exp_bits - 2; i >= 0; i--) {
        if (mpz_tstbit(exp2, i)) {
            mpz_mul(res, res, pp->table[i]);
            mpz_mod(res, res, pp->mod);
        }
    }
    /* inverte il risultato se 'exp' era negativo */
    if (mpz_sgn(exp) == -1) {
        if (!mpz_invert(res, res, pp->mod))
            mpz_set_ui(res, 0L);
    }
    mpz_clear(exp2);
}

/* precomputazione relativa all'esponenziazione modulare a finestra fissa
 * tramite 'mpz_pp_window_powm' */
void mpz_pp_window_powm_init(mpz_pp_window_powm_t pp, size_t exp_bits,
                             size_t window_size, const mpz_t base,
                             const mpz_t mod) {
    assert(pp);
    assert(exp_bits > 0);
    assert(window_size > 0);
    assert(base);
    assert(mod);

    pp->window_size = window_size;
    pp->window_base = 1 << window_size;

    pp->exp_b_digits = (size_t)ceilf((float)exp_bits / (float)window_size);
    assert(pp->exp_b_digits > 0);
    pp->table = (mpz_t *)malloc(sizeof(mpz_t) * pp->exp_b_digits);
    assert(pp->table);
    pp->exp_bits = exp_bits;

    mpz_init_set(pp->mod, mod);

    for (size_t i = 0; i < pp->exp_b_digits; i++)
        mpz_init(pp->table[i]);

    mpz_set(pp->table[0], base);
    for (size_t i = 1; i < pp->exp_b_digits; i++)
        mpz_powm_ui(pp->table[i], pp->table[i - 1], pp->window_base, mod);
}

/* esponenziazione modulare a finestra fissa (a rango k) con precomputazione */
void mpz_pp_window_powm(mpz_t res, const mpz_t exp,
                        const mpz_pp_window_powm_t pp) {
    mpz_t exp2, t;
    size_t exp_bits, exp_b_digits;

    assert(res);
    assert(exp);
    assert(res != exp);
    assert(pp);
    assert(pp->window_size > 0);
    assert(pp->window_base > 0);

    if (mpz_cmp_ui(exp, 0) == 0) {
        mpz_set_ui(res, 1);
        return;
    }

    mpz_init(t);
    mpz_init(exp2);
    mpz_abs(exp2, exp);
    exp_bits = mpz_sizeinbase(exp2, 2);

    assert(exp_bits <= pp->exp_bits);
    assert(exp_bits >= 1);
    assert(mpz_tstbit(exp2, exp_bits - 1));

    exp_b_digits = (size_t)ceilf((float)exp_bits / (float)pp->window_size);
    assert(exp_b_digits <= pp->exp_b_digits);
    unsigned long exp_in_base_b[exp_b_digits];
    for (size_t i = 0; i < exp_b_digits; i++) {
        mpz_tdiv_r_2exp(t, exp2, pp->window_size);
        mpz_tdiv_q_2exp(exp2, exp2, pp->window_size);
        exp_in_base_b[i] = mpz_get_ui(t);
        assert(exp_in_base_b[i] >= 0);
        assert(exp_in_base_b[i] < pp->window_base);
    }
    mpz_set_ui(t, 1);   // B
    mpz_set_ui(res, 1); // A
    for (size_t j = pp->window_base - 1; j >= 1; j--) {
        for (size_t i = 0; i < exp_b_digits; i++)
            if (exp_in_base_b[i] == j) {
                mpz_mul(t, t, pp->table[i]);
                mpz_mod(t, t, pp->mod);
            }
        mpz_mul(res, res, t);
        mpz_mod(res, res, pp->mod);
    }

    if (mpz_sgn(exp) == -1) {
        if (!mpz_invert(res, res, pp->mod))
            mpz_set_ui(res, 0L);
    }
    mpz_clears(exp2, t, NULL);
}

/* disallocazione della parte dinamica delle struttura di precomputazione */
void mpz_pp_powm_clear(mpz_pp_powm_t pp) {
    assert(pp);

    for (size_t i = 0; i < pp->exp_bits; i++)
        mpz_clear(pp->table[i]);
    free(pp->table);
    mpz_clear(pp->mod);
}

/* disallocazione della parte dinamica delle struttura di precomputazione */
void mpz_pp_window_powm_clear(mpz_pp_window_powm_t pp) {
    assert(pp);

    for (size_t i = 0; i < pp->exp_b_digits; i++)
        mpz_clear(pp->table[i]);
    free(pp->table);
    mpz_clear(pp->mod);
}
