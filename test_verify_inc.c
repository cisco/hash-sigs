/*
 * This bangs on the incremental version of the signature verification logic
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hss.h"
#include "hss_verify_inc.h"
#include "test_hss.h"

static bool generate_random(void *output, size_t length) {
    unsigned char *p = output;
    while (length--) {
        *p++ = rand() % 256;
    }
    return true;
}

/* This validates the message in step-sized pieces */
static bool do_validate( void *public_key,
                         const unsigned char *message, size_t len_message,
                         void *signature, size_t len_signature,
                         size_t step, enum hss_error_code *error ) {
    struct hss_validate_inc ctx;
    struct hss_extra_info info = { 0 };
    if (!hss_validate_signature_init( &ctx, public_key,
                       signature, len_signature, &info )) {
        if (error) *error = hss_extra_info_test_error_code( &info );
        return false;
    }

    size_t i, segment;
    unsigned char *buffer = malloc(step);
    if (!buffer) {
        if (error) *error = hss_error_out_of_memory;
        return false;
    }
    for (i = 0; i < len_message; i += segment) {
        segment = step;
        if (segment > len_message - i) segment = len_message - i;
        memcpy( buffer, &message[i], segment );
        if (!hss_validate_signature_update( &ctx,
                       buffer, segment )) {
                /* This shouldn't happen */
            if (error) *error = hss_range_processing_error;
            free(buffer);
            return false;
        }
    }
    free(buffer);

    bool success = hss_validate_signature_finalize( &ctx, signature, &info );
    if (error) *error = hss_extra_info_test_error_code( &info );
    return success;
}

static bool do_test(bool fast_flag, int max_d,
                param_set_t *lm_array, param_set_t *lm_ots_array) {
    int d;
    for (d=1; d<=max_d; d++) {
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
    
        size_t len_signature = hss_get_signature_len(d, lm_array, lm_ots_array );
        if (len_signature == 0) { 
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
    
        /* Load the private key into memory */
        struct hss_working_key *w = hss_load_private_key(
                               NULL, private_key,
                               0,     /* Minimal memory */
                               aux_data, sizeof aux_data, 0 );
        if (!w) {
            printf( "    *** failed loading private key\n" );
            return false;
        }
    
        unsigned char signature[len_signature];
        /*
         * Try correct validations, at various step levels
         */
        int step;
        for (step = 1; step < 70; step++) {
            /* Generate a valid signature */
            static unsigned char test_message[] =
              "The powers not delegated to the United States by the Constitution, "
              "nor prohibited by it to the States, are reserved to the States "
              "respectively, or to the people";
      
            if (!hss_generate_signature( w, NULL, private_key,
                                     test_message, sizeof test_message,
                                     signature, len_signature, 0 )) {
                printf( "    *** failed signing test message\n" );
                hss_free_working_key(w);
                return false;
            }
    
            if (!do_validate( public_key,
                              test_message, sizeof test_message,
                              signature, len_signature, step, 0 )) {
                printf( "    *** failed valid signature\n" );
                hss_free_working_key(w);
                return false;
            }
        }
    
        /* Try validating the wrong message (and reuse the signature we */
        /* generated above) */
        unsigned char wrong_message[] = "Wrong message";
        enum hss_error_code error;
        if (do_validate( public_key,
                              wrong_message, sizeof wrong_message,
                              signature, len_signature, 7, &error )) {
            printf( "    *** incorrect message validated\n" );
            hss_free_working_key(w);
            return false;
        }
        if (error != hss_error_bad_signature) {
            printf( "    *** incorrect error code\n" );
            hss_free_working_key(w);
            return false;
        }
    
        /* Corrupt the signature; check if we detect that */
        int i;
        unsigned char test_message[] =  "The powers ...";
      
        if (!hss_generate_signature( w, NULL, private_key,
                                     test_message, sizeof test_message,
                                     signature, len_signature, 0 )) {
            printf( "    *** failed signing test message\n" );
            hss_free_working_key(w);
            return false;
        }
        int count = 0;
        for (i=0; i<len_signature; i++) {
            int b;
                /* In fast mode, check every fifth bit */
            if (fast_flag) {
                count++; if (count != 5) continue; count = 0;
            }
            for (b = 0x01; b < 0x100; b <<= 1) {
                signature[i] ^= b;
                enum hss_error_code error;
                if (do_validate( public_key,
                              test_message, sizeof test_message,
                              signature, len_signature, sizeof test_message, 
                              &error )) {
                    printf( "    *** incorrect signature validated\n" );
                    hss_free_working_key(w);
                    return false;
                }
                if (error != hss_error_bad_signature) {
                    printf( "    *** incorrect error code\n" );
                    hss_free_working_key(w);
                    return false;
                }
                signature[i] ^= b;
            }
        }
            /* Check a too-short signature */
        if (do_validate( public_key,
                              test_message, sizeof test_message,
                              signature, len_signature - 1, sizeof test_message,
                              &error)) {
            printf( "    *** incorrect signature validated\n" );
            hss_free_working_key(w);
            return false;
        }
        if (error != hss_error_bad_signature) {
            printf( "    *** incorrect error code\n" );
            hss_free_working_key(w);
            return false;
        }
    
            /* And double check that the correct signature passes */
        if (!do_validate( public_key,
                              test_message, sizeof test_message,
                              signature, len_signature, sizeof test_message, 0 )) {
            printf( "    *** error in test\n" );
            hss_free_working_key(w);
            return false;
        }
    
        hss_free_working_key(w);
    }

    return true;
}

#define MAX_D 4
bool test_verify_inc(bool fast_flag, bool quiet_flag) {
    int max_d = fast_flag ? 3 : MAX_D;

    {
        static param_set_t lm_array[MAX_D] = {
                                    LMS_SHA256_N24_H10, LMS_SHA256_N24_H5,
                                    LMS_SHA256_N24_H5, LMS_SHA256_N24_H5 };
        static param_set_t lm_ots_array[MAX_D] = {
                  LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W4,
                  LMOTS_SHA256_N24_W4, LMOTS_SHA256_N24_W4 };
        if (!do_test( fast_flag, max_d, lm_array, lm_ots_array))
            return false;
    }

    if (!fast_flag) {
        static param_set_t lm_array[MAX_D] = {
                                    LMS_SHA256_N32_H10, LMS_SHA256_N32_H5,
                                    LMS_SHA256_N32_H5, LMS_SHA256_N32_H5 };
        static param_set_t lm_ots_array[MAX_D] = {
                  LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4,
                  LMOTS_SHA256_N32_W4, LMOTS_SHA256_N32_W4 };
        if (!do_test( fast_flag, max_d, lm_array, lm_ots_array))
            return false;
    }

    return true;
}
