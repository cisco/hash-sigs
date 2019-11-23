/*
 * This test runs a fairly exhaustive test on the key loading functionality
 *
 * It runs 3000 parallel working keys of the same private key; working key i
 * will be loaded at step i, and then generate signatures from that point;
 * for example, at step 3, we'll have three working keys; one which was loaded
 * at index 0 (and has produced 3 signatures so far); one which was loaded
 * at index 1 (and has produced 2 signatures so far); one which was loaded
 * at index 2 (and has only produced one signature).  We check that every
 * working key generates the same signature at each step (as everything in the
 * signatures is based on the private key, the index, and the message, we
 * should expect this).
 *
 * The idea is that we perform a key load from every possible offset in the
 * tree; if any of the working key loads didn't perform properly (either
 * getting the current auth path wrong, or not setting up the hashes for a
 * future path), that key will generate a wrong signature.
 *
 * It also does a pretty decent test on whether our Merkle tree traversal
 * logic is always traversing properly.
 *
 * It takes 20 minutes to do a full test on my test machine 
 */
#include "hss.h"
#include "hash.h"
#include "test_hss.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PARM_SET  LMS_SHA256_N32_H5
#define PARM_SET_2 LMOTS_SHA256_N32_W2

#define LEVELS 3

#define MAX_ITER 3000
#define FAST_ITER 300    /* Number of iterations to run in fast more */

static bool generate_random(void *output, size_t length) {
    unsigned char *p = output;
    while (length--) {
        *p++ = rand() % 256;
    }
    return true;
}

static void *private_key_pointer;

bool test_key_load(bool fast_flag, bool quiet_flag) {
    bool success_flag = false;
    param_set_t parm_set[3] = { PARM_SET, PARM_SET, PARM_SET };
    param_set_t ots_parm_set[3] = { PARM_SET_2, PARM_SET_2, PARM_SET_2 };

    size_t len_private_key = hss_get_private_key_len(LEVELS, parm_set,
                                       ots_parm_set);
    if (len_private_key == 0) return false;
    unsigned char *private_key = malloc( len_private_key );
    unsigned char *orig_private_key = malloc( len_private_key );
    unsigned char *copy_private_key = malloc( len_private_key );
    if (!private_key || !orig_private_key || !copy_private_key) return false;

    unsigned len_public_key = hss_get_public_key_len(LEVELS, parm_set,
                                       ots_parm_set);
    if (len_public_key == 0 || len_public_key > HSS_MAX_PUBLIC_KEY_LEN) return false;
    unsigned char public_key[ HSS_MAX_PUBLIC_KEY_LEN ];

    unsigned char aux_data[2000];

    /* Generate the master private key that we'll use for everyone */
    private_key_pointer = private_key;
    unsigned char master_private_key[ HSS_MAX_PRIVATE_KEY_LEN ];
    if (!hss_generate_private_key( generate_random, 
                      LEVELS, parm_set, ots_parm_set,
                      NULL, master_private_key,
                      public_key, len_public_key,
                      aux_data, sizeof aux_data, 0)) {
        printf( "Public/private key gen failed\n" );
        return false;
    }
    private_key_pointer = NULL;

    int i;

    struct hss_working_key *w[ MAX_ITER+1 ];
    unsigned char *priv_key[ MAX_ITER+1 ];
    for (i = 0; i <= MAX_ITER; i++) { w[i] = 0; priv_key[i] = 0; }

    struct hss_working_key *master_w = hss_load_private_key(
                            0, 0, master_private_key,
                            0, aux_data, sizeof aux_data, 0);
    if (!master_w) {
        printf( "Master load failed\n" );
        return false;
    }

    unsigned iter;
    if (fast_flag) iter = FAST_ITER; else iter = MAX_ITER;

    unsigned len_signature = hss_get_signature_len(LEVELS, parm_set, ots_parm_set);
if (len_signature == 0) return false;
    unsigned char *signature = malloc( len_signature );
    unsigned char *copy_signature = malloc( len_signature );
    if (!signature || !copy_signature) return false;

    int percent = 0;
    for (i=0; i<iter; i++) {

        if (!quiet_flag) {
            /* Display the running percentage.  This function actually has */
            /* quadratic behavior, as it checks every working set that's */
            /* been created so far; we create a fresh one every iteration. */
            /* Out percentage accounts for that.  A pet peeve of mine is */
            /* progress bars that aren't accurate; make sure this one is */
            float new_percent = (100.0 * i * i) / iter / iter;
            if (new_percent >= percent+1) {
                percent = (int)new_percent;
                printf( "    %d%%   (iter %d)\r", percent, i );
                fflush(stdout);
            }
        }

        /* Allocate the next working set */
            /* Use more memory for most of the working keys */
            /* By varying the memory irregularly (mod 7 is irregular for */
            /* a binary-based tree), we have a better change at tickling */
            /* a tree-walking bug */
        size_t memory_target = (i % 7 == 5) ? 0 : 30000;

        /* Create a fresh working set at the current index */
        /* Of course, in practice, we should *never* copy the private keys */
        /* around like this */
        private_key_pointer = private_key;
        int private_key_len = hss_get_private_key_len(LEVELS,
                                                 parm_set, ots_parm_set);
        priv_key[i] = malloc( private_key_len );
        if (!priv_key[i]) { printf( "Out of memory\n" ); goto failed; }
        memcpy( priv_key[i], master_private_key, private_key_len );

        struct hss_extra_info info = { 0 };
        w[i] = hss_load_private_key( 0, 0, priv_key[i],
                memory_target,
                (i % 3 == 1) ? NULL : aux_data, sizeof aux_data, &info );
        private_key_pointer = NULL;
        if (!w[i]) { printf( "load error %d at step %d\n", (int)info.error_code, i ); goto failed; }

        memcpy( orig_private_key, private_key, len_private_key );

        /* Generate a bunch of signatures of the same text */
        char text[ 100 ];
        unsigned len_text = sprintf( text, "Message #%d", i );

        /* Generate a signature from the master key.  This has the side */
        /* effect of incrementing the master private key */
        private_key_pointer = private_key;
        if (!hss_generate_signature( master_w,
                text, len_text,
                signature, len_signature, 0)) {
            printf( "\nMaster generate signature failed\n" );
            goto failed;
        }
        private_key_pointer = NULL;

        /* If we're doing a regression test, we really have to actually */
        /* check the signatures, even if it's not the point of the test */
        if (!hss_validate_signature( public_key, text,
                       len_text, signature, len_signature, 0 )) {
            printf( "\nVerify signature failed\n" );
            goto failed;
        }

        /* Now, go through and see if all the other working keys generate */
        /* the same signature */
        int j;
        for (j=0; j<=i; j++) {
            memcpy( copy_private_key, orig_private_key, len_private_key );

            private_key_pointer = copy_private_key;
            if (!hss_generate_signature( w[j],
                text, len_text,
                copy_signature, len_signature, 0)) {
                printf( "\nGenerate signature %d failed\n", j );
                goto failed;
            }
            private_key_pointer = NULL;

            /* The signature and the private key should be the same as */
            /* the master */
            if (0 != memcmp( signature, copy_signature, len_signature )) {
                printf( "\nError: signature %d not identical\n", j );
                goto failed;
            }
            if (0 != memcmp( private_key, copy_private_key, len_private_key )) {
                printf( "\nError: private_key %d not identical\n", j );
                goto failed;
            }
        }
    }
    success_flag = true;

failed:
    if (!quiet_flag) printf( "\n" );
    free(private_key);
    free(orig_private_key);
    free(copy_private_key);
    free(signature);
    free(copy_signature);
    for (i = 0; i <= MAX_ITER; i++) hss_free_working_key(w[i]);
    for (i = 0; i <= MAX_ITER; i++) free(priv_key[i]);
    hss_free_working_key(master_w);
    private_key_pointer = NULL;

    return success_flag;
}
