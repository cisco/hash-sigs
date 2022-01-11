/*
 * This bangs on the incremental version of the signature generation logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hss.h"
#include "hss_sign_inc.h"
#include "test_hss.h"

static bool generate_random(void *output, size_t length) {
    unsigned char *p = output;
    int i = 1;
    while (length--) {
        *p++ = i++;
    }
    return true;
}

/* We have no reason to write the key updates anywhere */
static bool ignore_update(unsigned char *private_key, size_t len, void *ctx) {
    return true;
}

static bool run_test(int d, param_set_t *lm_array, param_set_t *lm_ots_array,
                     unsigned num_iter, bool at_end) {
    size_t len_private_key = hss_get_private_key_len(d, lm_array, lm_ots_array );
    if (len_private_key == 0 || len_private_key > HSS_MAX_PRIVATE_KEY_LEN) { 
        printf( "    Len private key failed\n" );
        return false;
    }
    unsigned char private_key[HSS_MAX_PRIVATE_KEY_LEN];

    unsigned len_public_key = hss_get_public_key_len(d, lm_array, lm_ots_array );
    if (len_public_key == 0 || len_public_key > HSS_MAX_PUBLIC_KEY_LEN) { 
        printf( "    Len public key failed\n" );
        return false;
    }

    size_t len_sig = hss_get_signature_len(d, lm_array, lm_ots_array );
    if (len_sig == 0) { 
        printf( "    Len signature failed\n" );
        return false;
    }

    unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];

    unsigned char aux_data[1000];

    /* Generate the public key */
    if (!hss_generate_private_key(
                generate_random,
                d, lm_array, lm_ots_array,
                NULL, private_key,
                public_key, len_public_key,
                aux_data, sizeof aux_data, 0 )) {
        printf( "    Gen private key failed\n" );
        return false;
    }

    /* Load the private key into memory (twice!) */
    struct hss_working_key *w = hss_load_private_key(
                           NULL, private_key,
                           0,     /* Minimal memory */
                           aux_data, sizeof aux_data, 0 );
    struct hss_working_key *w2 = hss_load_private_key(
                           NULL, private_key,
                           0,     /* Minimal memory */
                           aux_data, sizeof aux_data, 0 );
    if (!w || !w2) {
        printf( "    *** failed loading private key\n" );
        hss_free_working_key(w);
        hss_free_working_key(w2);
        return false;
    }

    unsigned i;
    unsigned char *sig_1 = malloc(len_sig);
    unsigned char *sig_2 = malloc(len_sig);
    if (!sig_1 || !sig_2) {
        free(sig_1); free(sig_2);
        return false;
    }
    for (i = 0; i<num_iter; i++) {

        /* Generate a signature using the standard API */
        unsigned char message[3] = "ABC";
        if (!hss_generate_signature( w, ignore_update, NULL,
                   message, sizeof message,
                   sig_1, len_sig, 0 )) {
            printf( "    *** failed normal signature\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }

        /* Now, do the same using the incremental API */
        struct hss_sign_inc ctx;
        struct hss_extra_info info;
        hss_init_extra_info( &info );
        if (!hss_sign_init(&ctx, w2, ignore_update, NULL,
                sig_2, len_sig, &info )) {
            printf( "    *** failed signature init\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }

        /* Check if the hit-end flag we were returned is what we should */
        /* expect */
        if (hss_extra_info_test_last_signature(&info) !=
                                      (at_end && (i+1 == num_iter))) {
            printf( "    *** at-end flag not correct\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }


        if (!hss_sign_update( &ctx, "A", 1) ||
            !hss_sign_update( &ctx, "BC", 2)) {
            printf( "    *** failed signature update\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }

        if (!hss_sign_finalize( &ctx, w2, sig_2, 0)) {
            printf( "    *** failed signature finalize\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }

        /* Check if the two signatures are the same */
        if (0 != memcmp( sig_1, sig_2, len_sig )) {
            printf( "   *** Generated different signatures\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }
    }

    /* If we're supposed to be at the end, make sure asking for another */
    /* signature fails */
    if (at_end) {
        struct hss_sign_inc ctx;
        struct hss_extra_info info = { 0 };
        if (hss_sign_init(&ctx, w2, ignore_update, NULL,
                sig_2, len_sig, &info )) {
            printf( "    *** signinit succeeded when it should have failed\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }
        if (hss_extra_info_test_error_code(&info) != hss_error_private_key_expired) {
            printf( "    *** signinit gave incorrect error code\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig_1); free(sig_2);
            return false;
        }
    }

    hss_free_working_key(w);
    hss_free_working_key(w2);
    free(sig_1); free(sig_2);
    return true;
}

static bool run_test_2(int d, param_set_t *lm_array, param_set_t *lm_ots_array,
                     unsigned num_iter) {

    size_t len_private_key = hss_get_private_key_len(d, lm_array, lm_ots_array );
    if (len_private_key == 0 || len_private_key > HSS_MAX_PRIVATE_KEY_LEN) { 
        printf( "    Len private key failed\n" );
        return false;
    }
    unsigned char private_key[HSS_MAX_PRIVATE_KEY_LEN];

    unsigned len_public_key = hss_get_public_key_len(d, lm_array, lm_ots_array );
    if (len_public_key == 0 || len_public_key > HSS_MAX_PUBLIC_KEY_LEN) { 
        printf( "    Len public key failed\n" );
        return false;
    }

    size_t len_sig = hss_get_signature_len(d, lm_array, lm_ots_array );
    if (len_sig == 0) { 
        printf( "    Len signature failed\n" );
        return false;
    }

    unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];

    unsigned char aux_data[1000];

    /* Generate the public key */
    if (!hss_generate_private_key(
                generate_random,
                d, lm_array, lm_ots_array,
                NULL, private_key,
                public_key, len_public_key,
                aux_data, sizeof aux_data, 0 )) {
        printf( "    Gen private key failed\n" );
        return false;
    }

    /* Load the private key into memory (twice!) */
    struct hss_working_key *w = hss_load_private_key(
                           NULL, private_key,
                           0,     /* Minimal memory */
                           aux_data, sizeof aux_data, 0 );
    struct hss_working_key *w2 = hss_load_private_key(
                           NULL, private_key,
                           0,     /* Minimal memory */
                           aux_data, sizeof aux_data, 0 );
    if (!w || !w2) {
        printf( "    *** failed loading private key\n" );
        hss_free_working_key(w);
        hss_free_working_key(w2);
        return false;
    }

    unsigned char *sig = malloc( len_sig * num_iter );
    struct hss_sign_inc *ctx = malloc(sizeof(struct hss_sign_inc) * num_iter);
    unsigned char *sig_2 = malloc(len_sig);
    if (!sig || !ctx || !sig_2) {
        printf( "    *** memory allocation failure\n" );
        hss_free_working_key(w);
        hss_free_working_key(w2);
        free(sig); free(ctx); free(sig_2);
        return false;
    }
    unsigned i;
    for (i = 0; i<num_iter; i++) {

        /* Start the signature with the incremental API */
        if (!hss_sign_init(&ctx[i], w2, ignore_update, NULL,
                &sig[i * len_sig], len_sig, 0 )) {
            printf( "    *** failed signature init\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }

        /* Start updating */
        if (!hss_sign_update( &ctx[i], "AB", 2)) {
            printf( "    *** failed signature update\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }
    }

    for (i = 0; i<num_iter; i++) {

        /* Generate a signature using the standard API */
        unsigned char message[3] = "ABC";
        if (!hss_generate_signature( w, ignore_update, NULL,
                   message, sizeof message,
                   sig_2, len_sig, 0 )) {
            printf( "    *** failed normal signature\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }

        /* Now, finish the signature with the incremental API */
        if (!hss_sign_update( &ctx[i], "C", 1)) {
            printf( "    *** failed signature update\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }

        if (!hss_sign_finalize( &ctx[i], w2, &sig[i * len_sig], 0)) {
            printf( "    *** failed signature finalize\n" );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }

        /* Check if the two signatures are the same */
        if (0 != memcmp( &sig[i * len_sig], sig_2, len_sig )) {
            printf( "   *** Generated different signatures i = %d\n", i );
            hss_free_working_key(w);
            hss_free_working_key(w2);
            free(sig); free(ctx); free(sig_2);
            return false;
        }
    }

    hss_free_working_key(w);
    hss_free_working_key(w2);
    free(sig); free(ctx); free(sig_2);
    return true;
}

bool test_sign_inc(bool fast_flag, bool quiet_flag) {

    /*
     * First set of tests; for several different parameter sets, create the
     * same key with two different working_keys; generate signatures with both
     * (one using the standard API, and one with the incremental, and see if
     * they match
     */
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N32_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N32_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N24_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N32_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N32_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N24_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHAKE256_N24_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHAKE256_N24_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHAKE256_N32_H5 };
        param_set_t lm_ots_array[1] = { LMOTS_SHAKE256_N32_W8 };
        if (!run_test( d, lm_array, lm_ots_array, 32, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N32_H10 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N32_W4 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHA256_N24_H10 };
        param_set_t lm_ots_array[1] = { LMOTS_SHA256_N24_W4 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHAKE256_N32_H10 };
        param_set_t lm_ots_array[1] = { LMOTS_SHAKE256_N32_W4 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 1;
        param_set_t lm_array[1] = { LMS_SHAKE256_N24_H10 };
        param_set_t lm_ots_array[1] = { LMOTS_SHAKE256_N24_W4 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N32_H5, LMS_SHA256_N32_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N32_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N24_H5, LMS_SHA256_N32_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N32_W4, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHAKE256_N24_H5, LMS_SHAKE256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHAKE256_N24_W4, LMOTS_SHAKE256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHAKE256_N32_H5, LMS_SHAKE256_N32_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHAKE256_N32_W4, LMOTS_SHAKE256_N32_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N24_W4, LMOTS_SHA256_N32_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 1024, true )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N32_H10, LMS_SHA256_N32_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N32_W8, LMOTS_SHA256_N32_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 100, false )) return false;
    }
    {
        int d = 2;
        param_set_t lm_array[2] = { LMS_SHA256_N24_H10, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[2] = { LMOTS_SHA256_N24_W8, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 100, false )) return false;
    }
    {
        int d = 3;
        param_set_t lm_array[3] = {
            LMS_SHA256_N24_H10, LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[3] = {
            LMOTS_SHA256_N24_W8, LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W2 };
        if (!run_test( d, lm_array, lm_ots_array, 2000, false )) return false;
    }

    /*
     * Second test; for one particular parm set, initiate a large number of
     * signature ops, but don't close them out; then, close them out in
     * order, and see if they match the normal signature.  This verifies that
     * stepping the tree past where the original auth path was doesn't mess
     * things up
     * In slow mode, we make sure to step past the first penultimate Merkle
     * tree (level 2 in this case), to make sure that we don't need the
     * original tree there to be valid; it takes too long for fast mode
     */
    {
        int d = 3;
        param_set_t lm_array[3] = {
            LMS_SHA256_N24_H10, LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        param_set_t lm_ots_array[3] = {
            LMOTS_SHA256_N24_W8, LMOTS_SHA256_N24_W8, LMOTS_SHA256_N24_W8 };
        int num_iter;
        if (fast_flag) num_iter = 100; else num_iter = 10000;
        if (!run_test_2( d, lm_array, lm_ots_array, num_iter )) return false;
    }

    return true;
}
