/*
 * This will test out the protection against fault attacks.  This LMS
 * implementation recomputes the same hash multiple times (both between
 * reloads and within a single reload cycle).
 * One concern is that if we were to miscompute such a hash one of those
 * times (and so miscompute the public key), we might end up signing one
 * public key with an OTS key, and then later signing a different public
 * key with the same OTS key,  This concern was first raised by
 * https://eprint.iacr.org/2018/674.pdf in the context of Sphincs; the
 * same concern is valid here.
 *
 * This package implements optional protection against this fault attack
 * (enabled by the FAULT_HARDENING flag); this regression test tries to
 * hammer at it to make sure that it gives as much protection as we would
 * hope.
 *
 * Here's how this test works; if TEST_INSTRUMENTATION is enabled, then
 * we can selectively inject hash faults (currently, we have 29 different
 * categories of fault locations); when triggered, the corresponding
 * SHA526 hash is wrong.  What we do is generate a number of HSS signatures
 * (periodically reloading the key; a fault during a key reload needs to
 * be checked), and for each such signature, we parse it into the LMS
 * signatures, and record for each signature, what was the I value
 * (public key id), and the J index; and the value that was signed (and
 * the C randomizer).  If we ever see the same OTS private key (I and J
 * values) signing two different messages (and C randomizer), we declare
 * failure.
 */
#include <stdio.h>
#include <string.h>
#include "hss.h"
#include "test_hss.h"
#include "hash.h"
#include "lm_common.h"

/* These 4 match the globals from the instrumentation in hash.c */
int hash_fault_enabled;  /* 0 -> act normally */
                         /* 1 -> miscompute a hash, as specified below */
                         /* 2 -> miscompute all hashes */
    /* These two specify which hashes this miscomputaton logic applies to */
    /* if hash_fault_enabled == 1 */
int hash_fault_level;    /* Specify the level of hashes we're interested in */
                         /* 0 -> root LMS level */
                         /* 1 -> the LMS tree below the root, etc */
int hash_fault_reason;   /* The reason the hash is done */
                         /* See hss_fault.h for the list */
long hash_fault_count;   /* Which hash to get wrong (count) */
                         /* 1 -> the very next hash */
                         /* Also is decremented on every matching hash */
                         /* computation */

/*
 * This will do an initial check if allowing this test to run makes sense
 * - If the hash function has not been instrumented, we can't inject
 *   failures (and so there's no point to this test)
 * - If the code doesn't have fault hardening enabled, then it won't have
 *   any defenses against faults, and so there's no point in checking
 */
bool check_fault_enabled(bool fast_flag) {
    bool allow_test_to_go_through = true;

    /* Check whether the LMS implementation claims to be hardened */
    /* against fault attacks.  Note: to test this test to see if it'll */
    /* detect faults, comment out the below lines */
    if (!hss_is_fault_hardening_on()) {
        printf( "  Fault hardening is not enabled - test of fault hardening logic skipped\n" );
        allow_test_to_go_through = false;
            /* Lets not bother the user with whether instrumentation was */
            /* turned on */
        return allow_test_to_go_through;
    }

    /* Check if we can inject a hash fault */
    unsigned char actual[MAX_HASH];
    hash_fault_enabled = 2;  /* Miscompute all hashes */
    hss_hash( actual, HASH_SHA256, "abc", 3 );
    hash_fault_enabled = 0;  /* Shut off fault testing */

    /* This is SHA256("abc"), assuming that we did compute it correctly */
    static unsigned char good_hash[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };

    if (0 == memcmp( actual, good_hash, 32 )) {
        printf( "  Test instrumentation logic not enabled - test skipped\n" );
        printf( "      Turn on TEST_INSTRUMENTATION flag to enable\n" );
        allow_test_to_go_through = false;
    }

    return allow_test_to_go_through;
}

/*
 * These are the fixed parameter set we'll use
 */
static param_set_t lm_array[3] = { LMS_SHA256_N32_H5, LMS_SHA256_N32_H5,
                                   LMS_SHA256_N32_H5 };
static param_set_t ots_array[3] = { LMOTS_SHA256_N32_W2, LMOTS_SHA256_N32_W2,
                                    LMOTS_SHA256_N32_W2 };
#define NUM_LEVELS 3

/*
 * This is the exemplar private key we'll use.
 */
static unsigned char private_key[HSS_MAX_PRIVATE_KEY_LEN];
static unsigned char aux_data[1000];

static bool rand_1(void *output, size_t len) {
    /* We really don't care what this is */
    memset( output, 0x03, len );
    return true;
}

static bool gen_private_key(void) {
    unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];
    return hss_generate_private_key( rand_1,
                                     NUM_LEVELS, lm_array, ots_array,
                                     0, private_key,
                                     public_key, sizeof public_key,
                                     aux_data, sizeof aux_data,
                                     0 );
}

#define FIRST_ITER      69  /* For the first iteration, generate 69 */
                            /* signatures between reloads.  This is sized */
                            /* so that second reload cycle starts in one */
                            /* bottom tree, and ends in another */
#define SECOND_ITER   1024  /* For the second iteration, generate 1024 */
                            /* signatures between reloads.  This is sized */
                            /* so that second reload cycle starts in one */
                            /* second level tree, and ends in another */
/*
 * This runs the standard set of key reloads and signature generation
 * We do the same sequence each time so that we perform the same hashes
 * each time
 * If allow_app_to_get_stats is provided, it'll be called at specific points
 * while the test is running
 * If store_signature is provided, it'll be called with the generated
 * signatures
 *
 * The sequence of operations it performs is:
 * - Key load
 * - Generate the next N signatures
 * (Point 0)
 * - Key load
 * (Point 1)
 * - Generate the next N signatures
 * (Point 2)
 * - Key load
 * - Generate the next N signatures
 *
 * This will call allow_app_to_get_stats at points 0, 1, 2; that records
 * the data that'll allow a later run to target the hash fault either in
 * the second key laod or the second set of signatures (depending on which
 * we are testing).
 *
 * The idea behind this sequence is to allow the fault logic to target
 * a fault either during the second key load (between points 0 and 1), or
 * during the second set of signatures (between points 1 and 2).
 * That is, if a fault during a key load causes us to corrupt our internal
 * structures (without being detected), we'll see an inconsistancy between
 * the first set of signatures and the second.
 * And, if a fault during a signature generation causes us to corrupt our
 * internal structures, we'll see an inconsistancy between and second set
 * of signatures and the third.
 */
static bool run_iteration(int iter, bool fail_on_error,
           void (*allow_app_to_get_stats)(int when, void *context),
           bool (*store_signature)(const unsigned char *signature, int len_sig,
                                   void *context),
           void *context) {
    struct hss_extra_info info = { 0 };
    hss_extra_info_set_threads( &info, 1 );  /* Shut off multithreading */
        /* We tell the code 'cause the 7th hash from now to fail'; if the */
        /* hashes are computed in parallel, which one is the 7th becomes */
        /* problematic */

    /* Create a local copy of the private key */
    /* No, you *REALLY* shouldn't do this in a real application */
    unsigned char my_private_key[HSS_MAX_PRIVATE_KEY_LEN];
    memcpy( my_private_key, private_key, HSS_MAX_PRIVATE_KEY_LEN );

    int len_signature = 0;
    unsigned char *signature = 0;

    int i;
    /*
     * We go through 3 reload cycles; one good one, one where the fault
     * actually haapens, and then another good one
     */
    for (i=0; i<3; i++) {
        if (i == 1 && allow_app_to_get_stats)
            allow_app_to_get_stats(0, context);  /* Point 0 */
        /*
         * Every so often, reload the private key
         */
        struct hss_working_key *w = hss_load_private_key(
                   0, 0, my_private_key,
                   100000, aux_data, sizeof aux_data,
                   &info);
        if (i == 1 && allow_app_to_get_stats)
            allow_app_to_get_stats(1, context);  /* Point 1 */

        if (!w) {
            if (fail_on_error) {
                 /* Huh?  We haven't injected a fault */
                 /* This should have worked */
                 free(signature);
                 return false;
            }
            /* Perhaps we failed because of an internal fault; try again */
            continue;
        }
        if (!signature) {
            len_signature = hss_get_signature_len_from_working_key(w);
            signature = malloc(len_signature);
            if (!signature) { hss_free_working_key(w); return false; }
        }

        /*
         * And then generate a series of signatures
         * On the second iteration, we go over 1024 signatures (so that
         * we start in one top OTS key, go to the next, and then go to
         * a third -- more chances to hit a vulnerability)
         */
        int j;
        for (j=0; j<FIRST_ITER + (SECOND_ITER-FIRST_ITER)*iter; j++) {
            bool success = hss_generate_signature(w, "abc", 3,
                            signature, len_signature,
                            &info );
            if (!success) {
                /* The signature generation failed, possibly because of */
                /* the injected fault */
                if (fail_on_error) {
                     /* Hey, we weren't injecting faults; something */
                     /* is wrong */
                     free(signature);
                     hss_free_working_key(w);
                     return false;
                }
                continue;
            }

            if (store_signature &&
                  !store_signature( signature, len_signature, context )) {
                free(signature);
                hss_free_working_key(w);
                return false;
            }
        }
        hss_free_working_key(w);

        if (i == 1 && allow_app_to_get_stats)
            allow_app_to_get_stats(2, context);  /* Point 2 */
    }

    free(signature);
    return true;
}

/*
 * This is the data structure that tracks which messages have been
 * signed by which OTS key
 */
struct seen_hash {
    struct seen_hash *link;
    unsigned char I[16];   /* The LMS public key that signed the message */
    unsigned char q[4];    /* The LMS-OTS index that signed it */
    unsigned char *message; /* The message that was signed */
    unsigned len_msg;
    unsigned char c[32];   /* The randomizer used - because it's hashed */
                           /* with the message, a change here will also */
                           /* allow a forgery */
};

/*
 * Hash table of signed messages that we've seen so far
 */
struct database {
    struct seen_hash *hash_table[256];

    /* These aren't actually part of the database; it's just a convenient */
    /* way to pass these values */
    unsigned len_sig;
    unsigned len_pk;
};

/* The hash function we use */
static int hash( const unsigned char *I, const unsigned char *q) {
     return (I[0] ^ q[3]) & 0xff;
}

static void init_database(struct database *d) {
    int i;
    for (i=0; i<256; i++) d->hash_table[i] = 0;
}

/*
 * This inserts a signature into the database (and checks to see if
 * we've seen the same i/q value with a different message)
 */
static bool insert_database(struct database *d,
                            const unsigned char *i, const unsigned char *q,
                            const unsigned char *message, unsigned len_msg,
                            const unsigned char *c) {
    int h = hash(i, q);
    struct seen_hash *p;
    for (p = d->hash_table[h]; p; p = p->link) {
        if (0 == memcmp( i, p->I, 16 ) &&
            0 == memcmp( q, p->q, 4 )) {
            /* We've seen this entry before */
            if (p->len_msg == len_msg &&
                0 == memcmp( p->message, message, len_msg ) &&
                0 == memcmp( p->c, c, 32)) {
                /* Exact duplicate; ignore */
                return true;
            }

            /*
             * We detected the event that would allow a forgery
             */
            printf( " Discovered same OTS index signing two different messages\n" );
            return false;
       }
    }

    /* Not seen before; insert it */
    p = malloc( sizeof *p); if (!p) return false;
    p->message = malloc( len_msg ); if (!p->message) { free(p); return false; }

    memcpy( p->I, i, 16 );
    memcpy( p->q, q, 4 );
    memcpy( p->message, message, len_msg );
    memcpy( p->c, c, 32 );
    p->len_msg = len_msg;
    p->link = d->hash_table[h];
    d->hash_table[h] = p;
    return true;
}

static void delete_database(struct database *d) {
    int i;
    for (i=0; i<256; i++) {
        while (d->hash_table[i]) {
            struct seen_hash *p = d->hash_table[i];
            d->hash_table[i] = p->link;
            free(p->message);
            free(p);
        }
    }
}

/*
 * This takes an HSS signature, parses it into the component LMS
 * sigantures/messages, and inserts those into the databae
 */
static bool store_sigs( const unsigned char *signature, int len_sig,
                                   void *context) {
    struct database *d = context;

    signature += 4; len_sig -= 4; /* Skip over the number of levels */

    int i;
    for (i=0; i<NUM_LEVELS; i++) {
        /* Get the I value from the public key */
        unsigned char I[16];
        if (i == 0) {
            /* Root hash; we could save it from the HSS public key; but */
            /* it's easier to pass in a fixed value (as we only see one */
            /* root) */
            memset( I, 0, 16 );
        } else {
            if (len_sig < d->len_pk) return false;
            memcpy( I, signature+8, 16 );
            signature += d->len_pk; len_sig -= d->len_pk;
        }

        /* Get the actual signature */
        const unsigned char *ots_sig = signature;
        unsigned len_ots_sig = d->len_sig;
        if (len_sig < len_ots_sig) return false;
        const unsigned char *c = ots_sig+8;   /* Grab the randomizer */
        signature += len_ots_sig; len_sig -= len_ots_sig;

        /* Get the message that was signed */
        const unsigned char *message;
        int len_msg;
        if (i == NUM_LEVELS-1) {
            message = (void *)"abc";
            len_msg = 3;
        } else {
            message = signature;
            len_msg = d->len_pk;
        }

        /* Log it */
        if (!insert_database(d, I, ots_sig, message, len_msg, c )) {
            return false;
        }
    }
    return true;
}

/*
 * This records the number of matching hashes we get at the three points
 * we've defined (before the second reload, after the second reload and
 * after the second sequence of signature generation
 */
static void get_stats( int index, void *p ) {
    unsigned long *count = p;
    count[index] = -hash_fault_count;
}

#define NUM_REASON 8   /* Currently, the LMS code defines 8 distinct reasons */
                       /* (see hss_fault.h for the current list) */
 
bool test_fault(bool fast_flag, bool quiet_flag) {
    /* Create the exemplar private key */
    if (!gen_private_key()) return false;

    int iter;
    int max_iter = (fast_flag ? 1 : 2);
    int percent = 0;
    for (iter = 0; iter < max_iter; iter++) {
        float start_range, stop_range;

        if (fast_flag) {
            start_range = 0; stop_range = 1;
        } else {
            float mid_range = (float)FIRST_ITER / (float)SECOND_ITER;
            if (iter == 0) {
                start_range = 0; stop_range = mid_range;
            } else {
                start_range = mid_range; stop_range = 1;
            }
        }

        /*
         * This is the number of hashes done while performing
         * the test sequence, listed by hyper tree level and
         * hash reason
         * Last index:
         *  0 -> # of hashes done at the start of the second key reload
         *  1 -> # of hashes done at the end of the second key reload
         *  2 -> # of hashes done at the end of the second sequnce of
         *       signature generation
         *  3 -> total # of hashes done
         */
        unsigned long count_hashes[NUM_LEVELS][NUM_REASON][4];

        /*
         * Count the number of times we compute each hash reason
         * and more particularly, when we would need to time the
         * failure so that it happens either during the second rekey reload
         * or during the second set of signature generation
         */
        int level, reason;
        int total_tests = 0;
        for (level = 0; level < NUM_LEVELS; level++) {
            for (reason = 0; reason < NUM_REASON; reason++) {
                hash_fault_enabled = 1;
                hash_fault_level = level;
                hash_fault_reason = reason;
                hash_fault_count = 0;  /* By setting count == 0, we */
                    /* don't actually miscompute any hashes; however */
                    /* hash_fault_count is still decremented every */
                    /* time we get a match */
                bool success = run_iteration(iter, true, get_stats, 0, 
                                  &count_hashes[level][reason][0]);
                hash_fault_enabled = 0;
                if (!success) return false;
                count_hashes[level][reason][3] = -hash_fault_count;
#if 0
    /* Useful printout if you're curious */
                printf( "%d:%d - %ld %ld %ld %ld\n", level, reason,
                           count_hashes[level][reason][0],
                           count_hashes[level][reason][1],
                           count_hashes[level][reason][2],
                           count_hashes[level][reason][3] );
#endif
                total_tests += count_hashes[level][reason][1] >
                                      count_hashes[level][reason][0];
                total_tests += count_hashes[level][reason][2] >
                                      count_hashes[level][reason][1];
            }
        }

        /*
         * For each hash reason that could occur at least once, make one
         * of those hashes fail once (about half way through)
         */
        int tests_run = 0;
        for (level = 0; level < NUM_LEVELS; level++) {
            for (reason = 0; reason < NUM_REASON; reason++) {
                int z;
                for (z = 0; z<2; z++) {
                    /* If z = 0, we'll trigger the fault during the reload */
                    /* If z = 1, we'll trigger the fault during a sig gen */
                    if (count_hashes[level][reason][z] ==
                        count_hashes[level][reason][z+1]) {
                        /* We don't compute that specific hash type then */
                        continue;
                   }

                   if (!quiet_flag) {
                      float new_percent = (float)tests_run / total_tests;
                      new_percent = start_range + (stop_range - start_range) * new_percent;
                      new_percent *= 100;
                      if (new_percent >= percent+1) {
                          percent = (int)new_percent;
                          printf( "    %d%%\r", percent );
                          fflush(stdout);
                      }
                   }
                   tests_run++;
  
                   /* In -full mode, try various places for the hash */
                   /* function to fail; iterate from the 0% (the very */
                   /* first hash call) to the 100% (the very last */
                   /* hash call) in 10% increments */
                   /* In fast mode, just do the middle hash function */
                   int min_decade = fast_flag ? 5 : 0;
                   int max_decade = fast_flag ? 5 : 10;
                   int decade;
                   long prev_count = -1;
                   for (decade = min_decade; decade <= max_decade; decade++) {
                        /*
                         * Turn on the fault logic; targetting the specific
                         * hash type, and setting the count so that it'll fail
                         * at the spot we're testing
                         */
                        hash_fault_enabled = 1;
                        hash_fault_level = level;
                        hash_fault_reason = reason;
                        hash_fault_count = (
                           (10-decade) * (count_hashes[level][reason][z]+1) +
                            decade * count_hashes[level][reason][z+1]
                           ) / 10 ;
                        if (hash_fault_count == prev_count) {
                            /* This iteration would be precisely the same */
                            /* as the previous */
                            continue;
                        }
                        prev_count = hash_fault_count;

                        /* Create the table of signatures we've seen */
                        struct database seen_sigs;
                        init_database( &seen_sigs );
                        seen_sigs.len_sig = lm_get_signature_len(
                                     LMS_SHA256_N32_H5, LMOTS_SHA256_N32_W2 );
                        seen_sigs.len_pk = lm_get_public_key_len(
                                     LMS_SHA256_N32_H5);

#if 0
    /* Useful printout to let you see what the test is trying */
printf( "*** RUNNING TESTS with level = %d reason = %d z = %d %d0%%\n", level, reason, z, decade );
#endif
   
                        /* Run the test (with the specific failure */ 
                        bool success = run_iteration(iter, false, 0, store_sigs,
                                                 &seen_sigs);

                        /* Turn off failure testing */
                        hash_fault_enabled = 0;

                        delete_database( &seen_sigs );

                        /* If we detected a failure, we're done */
                        if (!success) return false;
                    }
                }
            }
        }

        if (iter+1 == max_iter) break;
        {
            /* Advance the exemplar private key by 511 */
            struct hss_working_key *w = hss_load_private_key(
                   0, 0, private_key, 0, aux_data, sizeof aux_data, 0);
            if (!w) return false;
            bool success = hss_reserve_signature( w, 511, 0 );
            hss_free_working_key(w);
            if (!success) return false;
        }
    }
    if (!quiet_flag) printf( "\n" );
    return true;
}
