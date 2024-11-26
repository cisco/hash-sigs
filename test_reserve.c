/*
 * This tests out the reservation; both the manual and the autoreserve
 *
 * The general strategy is to do reservations (both autoreserve and manual),
 * maintain a separate counter tracking when we ought to update the
 * private key, and see if we update it at the proper times (and by the
 * expected updates)
 */
#include "test_hss.h"
#include "hss.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int rand_seed;
static int my_rand(void) {
    rand_seed += rand_seed*rand_seed | 5;
    return rand_seed >> 9;
}
static bool rand_1( void *output, size_t len) {
    unsigned char *p = output;
    while (len--) *p++ = my_rand();
    return true;
}


static unsigned char priv_key[HSS_MAX_PRIVATE_KEY_LEN];
static unsigned long last_seqno; 
static bool got_update;
static bool got_error;
static bool hit_end;

static bool read_private_key(unsigned char *private_key,
            size_t len_private_key, void *context) {
    if (len_private_key > HSS_MAX_PRIVATE_KEY_LEN) return false;
    memcpy( private_key, priv_key, len_private_key );
    return true;
}

static bool update_private_key(unsigned char *private_key,
            size_t len_private_key, void *context) {
    if (len_private_key > HSS_MAX_PRIVATE_KEY_LEN || len_private_key < 8) return false;

    memcpy( priv_key, private_key, len_private_key );

    got_update = true;
    hit_end = false;
    got_error = false;

    int i;
    for (i=0; i<8; i++) {
        if (private_key[i] != 0xff) break;
    }
    if (i == 8) {
        hit_end = true;
        return true;
    }

    /* Our tests never have seqno's larger than 2**32-1 */
    /* If we see any larger claimed, it's an error */
    for (i=0; i<4; i++) {
        if (private_key[i] != 0x00) {
            got_error = true;
            return true;
        }
    }

    /* Pull out the sequence number from the private key */
    last_seqno = 0;
    for (i=4; i<8; i++) {
        last_seqno = 256*last_seqno + private_key[i];
    }

    return true;
}

bool test_reserve(bool fast_flag, bool quiet_flag) {
    int reserve, do_manual_res;

        /* d=1 makes it esay to extract the sequence number from */
        /* the signature */
    int default_d = 1;
    param_set_t default_lm_type[1] = { LMS_SHA256_N24_H10 };
    param_set_t default_ots_type[1] = { LMOTS_SHA256_N24_W2 };

    for (do_manual_res = 0; do_manual_res <= 1; do_manual_res++) {
        /* In full mode, we also run the tests skipping all manual */
        /* reservations; this makes sure that the autoreservations are */
        /* tested in all situations */
        if (fast_flag && !do_manual_res) continue;
    for (reserve = 0; reserve < 40; reserve++) {
        rand_seed = 2*reserve + do_manual_res;
        unsigned char pub_key[ 200 ];
        unsigned char aux_data[ 200 ];
        if (!hss_generate_private_key( rand_1,
            default_d, default_lm_type, default_ots_type,
            update_private_key, NULL,
            pub_key, sizeof pub_key,
            aux_data, sizeof aux_data,
            NULL)) {
             printf( "Error: unable to create private key\n" );
             return false;
        }

        struct hss_working_key *w = hss_load_private_key(
                read_private_key, NULL, 50000,
                aux_data, sizeof aux_data, NULL );
        if (!w) {
            printf( "Error: unable to load private key\n" );
            return false;
        }

        if (reserve > 0) {
            if (!hss_set_autoreserve(w, reserve, NULL)) {
                hss_free_working_key(w);
                printf( "Error: unable to do autoreseserve\n" );
                return false;
            }
        }

        unsigned i;
        unsigned reserved = 0;  /* Our model for how many are reserved */
        for (i=0; i<=1024; i++) {

            /* During the manual_res test, we randomly ask for manual */
            /* reservations */
            if (do_manual_res && (my_rand() & 0x1f) == 0x0d) {
                struct hss_extra_info info;
                unsigned manual_res = my_rand() & 0x0f;
                got_update = false;
                int success = hss_reserve_signature(w, update_private_key,
			       	NULL, manual_res, &info);

		/* We expect success if we're all the signatures we are */
		/* reserving are available */
		int expect_success = (i + manual_res) <= 1024;

		if (expect_success) {
		    if (!success) {
                        hss_free_working_key(w);
                        printf( "Error: unable to do manual reserve\n" );
                        return false;
		    }
                } else {
		    if (success) {
                        hss_free_working_key(w);
                        printf( "Error: manual reserve succeeded when it should have failed\n" );
                        return false;
		    }
		    if (hss_extra_info_test_error_code( &info ) != hss_error_not_that_many_sigs_left) {
                        hss_free_working_key(w);
                        printf( "Error: manual reserve did not get expected error code\n" );
                        return false;
		    }
		    manual_res = 0; /* We act as if nothing was reserved */
		                    /* (because it wasn't - the try failed) */
		}

                if (got_update && got_error) {
                    hss_free_working_key(w);
                    printf( "Error: manual reservation: set private key "
                            "to illegal value\n" );
                    return false;
                }
                if (manual_res <= reserved) {
                    if (got_update) {
                        hss_free_working_key(w);
                        printf( "Error: got update from manual "
                                "reservation: not expected\n" );
                        return false;
                    }
                } else {
                    if (!got_update) {
                        hss_free_working_key(w);
                        printf( "Error: no update from manual "
                                "reservation: expected one\n" );
                        return false;
                    }
                    if (hit_end) {
                        hss_free_working_key(w);
                        printf( "Error: manual reservation "
                                "invaliated key\n" );
                        return false;
                    }
                    if (manual_res + i != last_seqno) {
                        hss_free_working_key(w);
                        printf( "Error: manual reservation set "
                                "wrong seqno\n" );
                        return false;
                    }
                    reserved = manual_res;
                }
            }
            char message[ 100 ];
            size_t len_message = sprintf( message, "Message #%d", i );
            got_update = false;
            struct hss_extra_info info = { 0 };
            unsigned char signature[ 16000 ];
            if (!hss_generate_signature(w, update_private_key, NULL,
                     message, len_message,
                     signature, sizeof signature,
                     &info )) {
                hss_free_working_key(w);
                printf( "Error: unable to sign %d\n", info.error_code );
                return false;
            }

            /* Make sure that the index used in the signature is what we */
            /* expect */
            unsigned long sig_index = (signature[4] << 24UL) +
                                      (signature[5] << 16UL) +
                                      (signature[6] <<  8UL) +
                                      (signature[7]      );
            if (i != sig_index) {
                hss_free_working_key(w);
                printf( "Error: unexpected signature index\n" );
                return false;
            }

            if (got_update && got_error) {
                hss_free_working_key(w);
                printf( "Error: signature set private key "
                        "to illegal value\n" );
                return false;
            }
            if (reserved > 0 && i < 1023) {
                if (got_update) {
                    hss_free_working_key(w);
                    printf( "Error: siganture unexpectedly set "
                            "private key " );
                    return false;
                }
                reserved--;
            } else {
                if (!got_update) {
                    hss_free_working_key(w);
                    printf( "Error: siganture did not set private key " );
                    return false;
                }
                if (i == 1023) {
                    if (!hit_end) {
                        hss_free_working_key(w);
                        printf( "Error: reservation at end "
                                "did not invaliate key\n" );
                        return false;
                    }
                } else {
                    int expected_seqno = i + 1 + reserve;
                    if (expected_seqno >= 1024) expected_seqno = 1023;
                    if (hit_end) {
                        hss_free_working_key(w);
                        printf( "Error: reservation in middle "
                                "invaliated key\n" );
                        return false;
                    }
                    if (expected_seqno != last_seqno) {
                        hss_free_working_key(w);
                        printf( "Error: autoreservation set "
                                "unexpected sequence number\n" );
                        return false;
                    }
                    reserved = reserve;
                }
            }
            if (hss_extra_info_test_last_signature( &info )) {
                break;
            }
        }

        hss_free_working_key(w);
    } }

    return true;
}
