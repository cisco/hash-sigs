/*
 * This bangs on the signature verification logic
 */

#include <stdio.h>
#include <stdlib.h>
#include "hss.h"
#include "test_hss.h"

static param_set_t h_array[] = { 
    LMS_SHA256_N24_H5,
    LMS_SHA256_N32_H5,
    LMS_SHAKE256_N24_H5,
    LMS_SHAKE256_N32_H5,
    LMS_SHA256_N24_H10,
        /* We don't test out the higher heights, because that'd take too */
        /* long, and wouldn't tell us that much for this test */
};
#define MAX_H_INDEX (sizeof h_array / sizeof *h_array )

static param_set_t w_array[] = { 
    LMOTS_SHA256_N32_W1,
    LMOTS_SHA256_N24_W1,
    LMOTS_SHA256_N32_W2,
    LMOTS_SHA256_N24_W2,
    LMOTS_SHA256_N32_W4,
    LMOTS_SHA256_N24_W4,
    LMOTS_SHA256_N32_W8,
    LMOTS_SHA256_N24_W8,
    LMOTS_SHAKE256_N32_W1,
    LMOTS_SHAKE256_N24_W1,
    LMOTS_SHAKE256_N32_W2,
    LMOTS_SHAKE256_N24_W2,
    LMOTS_SHAKE256_N32_W4,
    LMOTS_SHAKE256_N24_W4,
    LMOTS_SHAKE256_N32_W8,
    LMOTS_SHAKE256_N24_W8,
};
#define MAX_W_INDEX (sizeof w_array / sizeof *w_array )
/* This is (roughly) the number of hash compression operatios needed to */
/* compute various OTS verifications.  This ignores a number of factors */
/* (SHA-256 vs SHAKE computations), however it should be within a couple */
/* orders of magnitude */
int cost_per_sig[MAX_W_INDEX] = {
    (1<<1) * 265,
    (1<<1) * 201,
    (1<<2) * 133,
    (1<<2) * 101,
    (1<<4) * 67,
    (1<<4) * 51,
    (1<<8) * 34,
    (1<<8) * 26,
    (1<<1) * 265,
    (1<<1) * 201,
    (1<<2) * 133,
    (1<<2) * 101,
    (1<<4) * 67,
    (1<<4) * 51,
    (1<<8) * 34,
    (1<<8) * 26,
};

static bool do_verify( unsigned char *private_key, unsigned char *public_key,
                       unsigned char *aux_data, size_t len_aux_data,
                       size_t signature_len, bool fast_flag );

static bool generate_random(void *output, size_t length) {
    unsigned char *p = output;
    while (length--) {
        *p++ = rand() % 256;
    }
    return true;
}

bool test_verify(bool fast_flag, bool quiet_flag) {
    int d;
    int i;
    struct {
        int d;
        param_set_t h;
        param_set_t w;
        float est_cost;
    } work_array[ 8 * MAX_H_INDEX * MAX_W_INDEX ];
    int w_count = 0;
    float total_cost = 0;

    /* Fill in the jobs we expect to do */
    int max_d = 0;
    for (d = 1; d <= 8; d++) {
        if (fast_flag && d > 3) continue;

        int h_index, w_index;
        for (h_index=0; h_index < MAX_H_INDEX; h_index++) {
        for (w_index=0; w_index < MAX_W_INDEX; w_index++) {
            param_set_t h = h_array[h_index];
            param_set_t w = w_array[w_index];
               /* Flag is set if we're testing out a W=8 parameter set */
            int w8 = (w == LMOTS_SHA256_N32_W8 || w == LMOTS_SHA256_N24_W8 ||
                      w == LMOTS_SHAKE256_N32_W8 ||
                      w == LMOTS_SHAKE256_N24_W8);
               /* Flag is set if we're testing out a W=4 parameter set */
            int w4 = (w == LMOTS_SHA256_N32_W4 || w == LMOTS_SHA256_N24_W4 ||
                      w == LMOTS_SHAKE256_N32_W4 ||
                      w == LMOTS_SHAKE256_N24_W4);

                /* Note: this particular combination takes longer than the */
                /* rest combined; it wouldn't tell us much more, so skip it */
            if (h == LMS_SHA256_N24_H10 && w8) continue;
                /* In fast mode, we both testing out W=8 only for d=1 */ 
            if (fast_flag && d > 1 && w8) continue;
            if (fast_flag && d > 2 && w4) continue;

            work_array[w_count].d = max_d = d;
            work_array[w_count].h = h;
            work_array[w_count].w = w;

            /* Compute the estimated cost */
            param_set_t lm_array[8], lm_ots_array[8];
            for (i=0; i<d; i++) { lm_array[i] = h; lm_ots_array[i] = w; }
            size_t sig_len = hss_get_signature_len(d, lm_array, lm_ots_array );
            if (sig_len == 0) continue;
            float est_cost = cost_per_sig[w_index] * sig_len;
            work_array[w_count].est_cost = est_cost;
            total_cost += est_cost;
            w_count++;
        } }
    }

    float cost_so_far = 0;
    int displayed_percent = 0;
    for (i=0; i<w_count; i++) {
        if (!quiet_flag) {
            int new_percent = (int)(100 * cost_so_far / total_cost);
            if (new_percent > displayed_percent) {
                printf( "    %d%%  (height = %d/%d)\r", new_percent, work_array[i].d, max_d );
                fflush(stdout);
                displayed_percent = new_percent;
            }
            cost_so_far += work_array[i].est_cost;
        }
        param_set_t lm_array[8], lm_ots_array[8];
        int j;
        int d = work_array[i].d;
        for (j=0; j<d; j++) { lm_array[j] = work_array[i].h;
                              lm_ots_array[j] = work_array[i].w; }
        for (   ; j<8; j++) { lm_array[j] = 0; lm_ots_array[j] = 0; }

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
        unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];

        size_t len_signature = hss_get_signature_len(d, lm_array, lm_ots_array );
        if (len_signature == 0) { 
            printf( "    Len signature failed\n" );
            return false;
        }

        unsigned char aux_data[1000];

        /* Gen a private key with that parameter set */
        if (!hss_generate_private_key(
                    generate_random,
                    d, lm_array, lm_ots_array,
                    NULL, private_key,
                    public_key, len_public_key,
                    aux_data, sizeof aux_data, 0 )) {
            printf( "    Gen private key failed\n" );
            return false;
        }

        /* Run tests; start at the initial position (seqno 0) */
        if (!do_verify( private_key, public_key, aux_data, sizeof aux_data, len_signature, fast_flag )) {
            return false;
        }

/* TODO: try at other sequence numbers */
    }

    if (!quiet_flag) printf( "\n" );

    return true;
}

/*
 * This will test out the signature at the current offset of the private key
 */
static bool do_verify( unsigned char *private_key, unsigned char *public_key,
                       unsigned char *aux_data, size_t len_aux_data,
                       size_t signature_len, bool fast_flag ) { 
    bool success = false;
    struct hss_working_key *w = 0;
    unsigned char *signature = malloc(signature_len);
    if (!signature) {
        printf( "    *** malloc failed\n" );
        goto failed;
    }

    /* Step 1: load the private key into memory */
    w = hss_load_private_key(
                           NULL, private_key,
                           0,     /* Minimal memory */
                           aux_data, len_aux_data, 0 );
    if (!w) {
        printf( "    *** failed loading private key\n" );
        goto failed;
    }

    /* Step 2: generate a valid signature */
    char test_message[3] = "abc";
  
    if (!hss_generate_signature( w, NULL, private_key,
                                 test_message, sizeof test_message,
                                 signature, signature_len, 0 )) {
        printf( "    *** failed signaing test message\n" );
        goto failed;
    }

    /* Make sure that the signature verifies correctly */
    if (!hss_validate_signature( public_key, test_message, sizeof test_message,
                                 signature, signature_len, 0)) {
        printf( "    *** verification failed when it should have passed\n" );
        goto failed;
    }

    /* Make sure that the signature fails if we pass the wrong message */
    char wrong_message[3] = "abd";
    struct hss_extra_info info = { 0 };
    if (hss_validate_signature( public_key, wrong_message, sizeof wrong_message,
                                 signature, signature_len, &info)) {
        printf( "    *** verification passed; should have failed (incorrect message)\n" );
        goto failed;
    }
    if (hss_extra_info_test_error_code(&info) != hss_error_bad_signature) {
        printf( "    *** incorrect error code (incorrect message)\n" );
        goto failed;
    }

    /* Make sure that the signature fails if the signature is too short */
    if (hss_validate_signature( public_key, test_message, sizeof test_message,
                                 signature, signature_len-1, &info)) {
        printf( "    *** verification passed; should have failed (signature too short)\n" );
        goto failed;
    }
    if (hss_extra_info_test_error_code(&info) != hss_error_bad_signature) {
        printf( "    *** incorrect error code (short sig)\n" );
        goto failed;
    }

    /* Now, go through the signature, and flip each bit; make sure that it fails */
    int i, b;
    for (i=0; i<signature_len; i++) {
        for (b = 0; b<8; b++) {
            /* In fast mode, only test some of the possible bit flips */
            if (fast_flag && (8*i + b) % 29 != 7) continue;

            signature[i] ^= (1<<b);

            if (hss_validate_signature( public_key, test_message, sizeof test_message,
                                 signature, signature_len, &info)) {
                printf( "    *** verification passed when it should have failed (flip bit %d, %d)\n", i, b );
                goto failed;
            }
            if (hss_extra_info_test_error_code(&info) != hss_error_bad_signature) {
                printf( "    *** incorrect error code (bit flip)\n" );
                goto failed;
            }

            signature[i] ^= (1<<b);
        }
    }
/* ... */

    success = true;
failed:
    hss_free_working_key(w);
    free(signature);
    return success;
}
