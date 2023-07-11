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

#ifndef LIB_POWM_H
#define LIB_POWM_H

#include <assert.h>
#include <gmp.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

struct mpz_pp_powm_struct {
    unsigned int exp_bits;
    mpz_t *table;
    mpz_t mod;
};
typedef struct mpz_pp_powm_struct *mpz_pp_powm_ptr;
typedef struct mpz_pp_powm_struct mpz_pp_powm_t[1];

struct mpz_pp_window_powm_struct {
    unsigned int window_size;
    unsigned int window_base;
    unsigned int exp_bits;
    unsigned int exp_b_digits;
    mpz_t *table;
    mpz_t mod;
};
typedef struct mpz_pp_window_powm_struct *mpz_pp_window_powm_ptr;
typedef struct mpz_pp_window_powm_struct mpz_pp_window_powm_t[1];

void mpz_naive_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                    const mpz_t mod);
void mpz_window_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                     const mpz_t mod, size_t window_size);
void mpz_swindow_powm(mpz_t res, const mpz_t base, const mpz_t exp,
                      const mpz_t mod, size_t max_window_size);
void mpz_pp_powm_init(mpz_pp_powm_t pp, size_t exp_bits, const mpz_t base,
                      const mpz_t mod);
void mpz_pp_powm(mpz_t res, const mpz_t exp, const mpz_pp_powm_t pp);
void mpz_pp_window_powm_init(mpz_pp_window_powm_t pp, size_t exp_bits,
                             size_t window_size, const mpz_t base,
                             const mpz_t mod);
void mpz_pp_window_powm(mpz_t res, const mpz_t exp,
                        const mpz_pp_window_powm_t pp);
void mpz_pp_powm_clear(mpz_pp_powm_t pp);
void mpz_pp_window_powm_clear(mpz_pp_window_powm_t pp);

#endif /* LIB_POWM_H */
