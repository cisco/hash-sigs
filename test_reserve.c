/*
 * This tests out the reservation; both the manual and the autoreserve
 *
 * The general strategy is to do reservations (both autoreserve and manual),
 * maintain a separate counter tracking when we ought to update the
 * private key, and see if we update it at the proper times (and by the
 * expected updates)
 *
 * This is made somewhat more tricky if FAULT_CACHE_SIG is turned on; that
 * also causes NVRAM updates at times; if that is turned on, then this checks
 * if those updates happen as well (and at the expected times)
 */
#include "test_hss.h"
#include "hss.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static unsigned rand_seed;
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
static int max_len_private_key; /* The actual length of the private key */

static bool read_private_key(unsigned char *private_key,
            size_t len_private_key, void *context) {
    if (len_private_key > HSS_MAX_PRIVATE_KEY_LEN) return false;
    memcpy( private_key, priv_key, len_private_key );
    return true;
}

static bool update_private_key(unsigned char *private_key,
            size_t len_private_key, void *context) {
    if (len_private_key > max_len_private_key ||
        len_private_key < 16) return false;

    memcpy( priv_key, private_key, len_private_key );

    /* Check to see if the update actually reflected everything */
    /* that actually changed in the private key */
    if (0 != memcmp( priv_key, private_key, max_len_private_key )) {
        /* Something was wrong - report an error */
        return false;
    }

    got_update = true;
    hit_end = false;
    got_error = false;

    int i;
    for (i=0; i<8; i++) {
        if (private_key[i+4] != 0xff) break;
    }
    if (i == 8) {
        hit_end = true;
        return true;
    }

    /* Our tests never have seqno's larger than 2**32-1 */
    /* If we see any larger claimed, it's an error */
    for (i=0; i<4; i++) {
        if (private_key[i+4] != 0x00) {
            got_error = true;
            return true;
        }
    }

    /* Pull out the sequence number from the private key */
    last_seqno = 0;
    for (i=4; i<8; i++) {
        last_seqno = 256*last_seqno + private_key[i+4];
    }

    return true;
}

static bool do_test( int default_d, param_set_t *default_lm_type,
                     param_set_t *default_ots_type, bool fast_flag,
                     bool verify_sig_index, bool expect_update_on_32) {
    int reserve, do_manual_res;

    max_len_private_key = hss_get_private_key_len( default_d,
                                  default_lm_type, default_ots_type );

    for (do_manual_res = 0; do_manual_res <= 1; do_manual_res++) {
        /* In full mode, we also run the tests skipping all manual */
        /* reservations; this makes sure that the autoreservations are */
        /* tested in all situations */
        if (fast_flag && !do_manual_res) continue;
    int max_reserve = (fast_flag ? 25 : 50);
    for (reserve = 0; reserve < max_reserve; reserve++) {
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
                read_private_key, update_private_key, NULL, 50000,
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
        int reserved = 0;  /* Our model for how many are reserved */
        for (i=0; i<=1024; i++) {

            /* During the manual_res test, we randomly ask for manual */
            /* reservations */
            if (do_manual_res && (my_rand() & 0x1f) == 0x0d) {
                unsigned manual_res = my_rand() & 0x0f;
                got_update = false;
                if (!hss_reserve_signature(w, manual_res, NULL)) {
                    hss_free_working_key(w);
                    printf( "Error: unable to do manual reserve\n" );
                    return false;
                }
                if (got_update && got_error) {
                    hss_free_working_key(w);
                    printf( "Error: manual reservation: set private key "
                            "to illegal value\n" );
                    return false;
                }
                if (manual_res > 1023 - i) manual_res = 1023 - i;
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
            if (!hss_generate_signature(w, message, len_message,
                     signature, sizeof signature,
                     &info )) {
                hss_free_working_key(w);
                printf( "Error: unable to sign %d\n", info.error_code );
                return false;
            }

            /* Make sure that the index used in the signature is what we */
            /* expect.  It's trickier when using a level > 1 param set */
            /* and doesn't really do any extra testing, so we skip it */
            if (verify_sig_index) {
                unsigned long sig_index = (signature[4] << 24UL) +
                                          (signature[5] << 16UL) +
                                          (signature[6] <<  8UL) +
                                          (signature[7]      );
                if (i != sig_index) {
                    hss_free_working_key(w);
                    printf( "Error: unexpected signature index\n" );
                    return false;
                }
            }

            if (got_update && got_error) {
                hss_free_working_key(w);
                printf( "Error: signature set private key "
                        "to illegal value\n" );
                return false;
            }

            /* Compute whether we expected an update */
            bool expected_update = (reserved <= 0 || i == 1023);
            /* When we are in CACHE_SIG mode, we'll also get updates when */
            /* we step into a tree that is partially reserved */
            if (expect_update_on_32 && (i % 32) == 31 && reserved < 32) {
                expected_update = true;
            }

            if (!expected_update) {
                if (got_update) {
                    hss_free_working_key(w);
                    printf( "Error: signature unexpectedly set "
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
                    int expected_seqno_2 = i + reserved;
                    if (expected_seqno_2 > expected_seqno) expected_seqno = expected_seqno_2;
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
                    reserved--;
                    if (reserved < reserve)
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

/*
 * This tests if the user has configured FAULT_CACHE_SIG
 */
static bool check_if_cache_sig_is_on(void) {
    return hss_is_fault_hardening_on( 1 );
}

bool test_reserve(bool fast_flag, bool quiet_flag) {

    {
	/* d=1 makes it esay to extract the sequence number from */
	/* the signature */
	int default_d = 1;
	param_set_t default_lm_type[1] = { LMS_SHA256_N32_H10 };
	param_set_t default_ots_type[1] = { LMOTS_SHA256_N32_W2 };

	if (!do_test( default_d, default_lm_type, default_ots_type,
                      fast_flag, true, false )) return false;
    }
    {
	/* try it again with a two level tree.  We actually do this to */
	/* stress out the FAULT_CACHE_SIG logic, which has some interaction */
	/* with the autoreserve logic */
	int default_d = 2;
	param_set_t default_lm_type[2] = { LMS_SHA256_N32_H5, LMS_SHA256_N32_H5 };
	param_set_t default_ots_type[2] = { LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W2 };

	if (!do_test( default_d, default_lm_type, default_ots_type,
                      fast_flag, false, check_if_cache_sig_is_on() )) return false;
    }

    return true;
}
