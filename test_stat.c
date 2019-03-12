/*
 * This is a statistical test of the HSS signatures.
 * Now, we're not questioning the statistical properties of SHA-256.  However,
 * SHA-256 has one statistical "failing", identical inputs will result in
 * identical outputs (actually, the entire HBS process depends on this, so
 * it's not really that serious of a failing).  So, what we're doing is
 * looking for duplicate hashes, which would imply duplicate inputs (or a
 * hash collision, which is *real* unlikely), which would imply a weakness.
 * Now, the LMS scheme mandates that the hash inputs are distinct, except in
 * three cases:
 * - The OTS private keys
 * - The I values
 * - The C randomizer (the part that is hashed along with the message)
 * Repeating OTS private keys is *BAD*, as it would give enough information
 * for an attacker to forge.  Repeating I values or C randomizers isn't nearly
 * as bad, it'd just reduce the security margin (in the case of I, allow
 * multitarget attacks; actually, the security proof accounts for it, however
 * it really shouldn't happen in the relatively small number of keys we use),
 * in the case of C, well, actually, collisions aren't an issue;
 * predictability is (and having a higher-than-expected collision probability
 * would make things predictable). Neither of these latter two would actually
 * be the end of the world, but they shouldn't happen; we might as well throw
 * those as well (especially since it makes the test easier).
 *
 * So, what we do is collect a series of signatures, and see if they contain
 * any duplicated hashes
 *
 * Also, when we're doing a multilevel HSS scheme, two different signatures
 * from the same Merkle level will contain the same upper level hashes (from
 * common aux path), we deliberately make sure we sample from different top
 * level signatures (and keep the same bottom level indexes; if there's a
 * problem there, this would show it up)
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "hss.h"
#include "test_hss.h"

/*
 * This is the parameter set we use (and the internal number of hashes)
 */
#define LM_PARAM  LMS_SHA256_N32_H5  /* Use as cheap of an LM path as */
                              /* possible; this is not what we're testing */
#define OTS_PARAM LMOTS_SHA256_N32_W1 /* Problems with the hash is */
                              /* more likely to show up here */
/* If you change the above params, the below need to be fixed as well */
/* Note: hashes are actually 32 bytes; however I values are 16, and we'd */
/* like to validate those against reuse */
/* The way to handle that is to claim to the infrastructure that we */
/* actually have 16 byte hashes (and twice as many, except for the I value) */
#define HASH_PER_OTS_SIG  (2*(1 + 265))
#define HASH_PER_LM_SIG   (2*5)
#define HASH_PER_PK   (1 + 2)
#define HASH_SIZE 16

#define LOG_HASH_PER_MERKLE_TREE 5 /* We use an H=5 parameter sets */
#define HASH_PER_MERKLE_TREE 32   /* We use an H=5 parameter sets */

static int rnd_count;

/*
 * This is the "randomness generator" we use for this test.  Obviously,
 * you shouldn't think of using this in a real program
 */
static bool generate_random(void *output, size_t length) {
    int n = rnd_count++;
    int i;
    unsigned char *p = output;
    for (i = length-1; i>=0; i--) {
        p[i] = n & 0xff;
        n >>= 8;
    }
    return true;
}

struct bin {
    unsigned char hash[HASH_SIZE];
        /* These bitfields track where the hash is from.  It doesn't help */
        /* us deciding whether the test passed or failed; it might give */
        /* insight as to the reason behind a failure */
    unsigned index : 9;   /* Index from start of region */
    unsigned region : 6;  /* Which region (sig/pk in signaure) */
    unsigned sig_num : 5; /* Which signature from the same key it's from */
    unsigned key_num : 2; /* Which key it's from */
    unsigned d : 3;       /* The d value we used */
};
static int compare_hash(const void *a, const void *b) {
    const struct bin *p = a;
    const struct bin *q = b;
    return memcmp(p->hash, q->hash, HASH_SIZE);
}
#define MAX_BIN 519936
   /* Yes, this is 10+Meg; if you don't have that much, get a real computer */

#define MAX_D 4

bool test_stat(bool fast_flag, bool quiet_flag) {
    rnd_count = 0;
    bool success = false;

    struct bin *t = malloc( MAX_BIN * sizeof *t );
    if (!t) {
        printf( "    Malloc failure\n" );
        return false;
    }
    long bin_count = 0;

    unsigned char *sig = 0;
    int d;
    for (d=1; d<=MAX_D; d++) {
        int k;
        param_set_t lm_type[MAX_D], lm_ots_type[MAX_D];
        int i;
        for (i=0; i<d; i++) {
            lm_type[i] = LMS_SHA256_N32_H5;
                /* We use W=1, as that's more likely to allow hash */
                /* failures to show up */ 
            lm_ots_type[i] = LMOTS_SHA256_N32_W1;
        }
        size_t pub_key_len =  hss_get_public_key_len(d, lm_type, lm_ots_type);
        size_t sig_len = hss_get_signature_len(d, lm_type, lm_ots_type);
        size_t priv_len = hss_get_private_key_len(d, lm_type, lm_ots_type);
        if (!pub_key_len || pub_key_len > HSS_MAX_PUBLIC_KEY_LEN ||
            !sig_len ||
            !priv_len || priv_len > HSS_MAX_PRIVATE_KEY_LEN) {
            printf( "    Bad parm set\n" );
            goto failed;
        }

        /* Try it for 3 distinct keys */
        for (k=0; k<3; k++) {
            unsigned char aux_data[200];
            unsigned char pub_key[HSS_MAX_PUBLIC_KEY_LEN];
            unsigned char private_key[HSS_MAX_PRIVATE_KEY_LEN];
            if (!hss_generate_private_key( generate_random,
                           d, lm_type, lm_ots_type,
                           NULL, private_key,
                           pub_key, pub_key_len,
                           aux_data, sizeof aux_data, 0 )) {
                printf( "    Pubkey gen failure\n" );
                goto failed;
            }

            struct hss_working_key *w = hss_load_private_key(
                      NULL, private_key, 0, aux_data, sizeof aux_data, 0);
            if (!w) {
                printf( "    Privkey load failure\n" );
                goto failed;
            }

            sig = malloc(sig_len); if (!sig) goto failed;
            
            for (i=0; i<HASH_PER_MERKLE_TREE; i++) {
                static char test_message[3] = "abc";
                /* Generate a signature */
                if (!hss_generate_signature(w, NULL, private_key,
                                            test_message, sizeof test_message,
                                            sig, sig_len, 0)) {
                    printf( "    Signature failure\n" );
                    hss_free_working_key(w);
                    goto failed;
                 }

                 /* Now, this test isn't here to check whether the */
                 /* signature generation process generates correct */
                 /* signatures, however it just feels wrong to not check */
                 if (!hss_validate_signature(pub_key,
                                  test_message, sizeof test_message,
                                  sig, sig_len, 0 )) {
                    printf( "    Signature validation failure\n" );
                    hss_free_working_key(w);
                    goto failed;
                 }

                 /* Now, scan through the signature, and collect all the hashes */
                 size_t sig_offset = 4;   /* Skip the initial num spk */
                 int j;
                 int region = 0;
                 for (j = 1;; j++) {
                     sig_offset += 8;   /* Skip the q and the OTS type */
#define deposit_hash( bin, bin_count, signature, sig_offset, num_hash, region, k, sig_id, d ) \
    { int n; for (n = 0; n<num_hash; n++) {                                           \
        if (bin_count == MAX_BIN) { printf( "   Error: MAX_BIN not large enough\n" ); \
                                    hss_free_working_key(w); goto failed; }           \
        memcpy( bin[bin_count].hash, &signature[sig_offset], HASH_SIZE );             \
        sig_offset += HASH_SIZE;                                                      \
        bin[bin_count].index = n;                                                     \
        bin[bin_count].region = region;                                               \
        bin[bin_count].key_num = k;                                                   \
        bin[bin_count].sig_num = sig_id;                                              \
        bin[bin_count].d = d;                                                         \
        bin_count++;                                                                  \
    } }
                     deposit_hash(t, bin_count, sig, sig_offset,
                                  HASH_PER_OTS_SIG, region, k, i, d);
                     region++;
                     sig_offset += 4;   /* Skip the LMS type */
                     if (j != 1) {
                         /* Non-topmost signature; we generate a fresh */
                         /* Merkle tree each time, so there really */
                         /* shouldn't be any repeats */
                         deposit_hash(t, bin_count, sig, sig_offset,
                                      HASH_PER_LM_SIG, region, k, i, d);
                         region++;
                     } else {
                         /* j==1 is the topmost signature; they'll be a */
                         /* lot of repeats in that (because that Merkle */
                         /* tree is fixed for a private key) */
                         sig_offset += HASH_SIZE * HASH_PER_LM_SIG;
                     }

                     if (j == d) break;
                     
                     /* Include the public key that follows */ 
                     sig_offset += 8;   /* Skip the LMS/OTS type */
                     deposit_hash(t, bin_count, sig, sig_offset,
                                  HASH_PER_PK, region, k, i, d);
                     region++;
                 }
if (sig_offset != sig_len) { printf( "Oops: we got something wrong here: %d %d\n", (int)sig_offset, (int)sig_len ); return false; }

                 if (i == 31) break;
                 if (d > 1) {
                     /* Hack to advance the key 32**(d-1) - 1 times */
                     /* We do this to make sure that the non-top Merkle */
                     /* trees we use are fresh */
                     if (!hss_reserve_signature( w, NULL, private_key,
                             (1L << (LOG_HASH_PER_MERKLE_TREE*(d-1))) - 1,
                             0)) {
                         printf( "    Reservation failure\n" );
                         hss_free_working_key(w);
                         goto failed;
                     }
                     if (!hss_generate_working_key( NULL, private_key,
                                          aux_data, sizeof aux_data, w,
                                          0 )) {
                         printf( "    Regeneration failure\n" );
                         hss_free_working_key(w);
                         goto failed;
                     }
                 }
            }
            hss_free_working_key(w);
        }
    }

    /*
     * Ok, we've collected all the hashes; now qsort them, and look for duplicates
     */
    qsort(t, bin_count, sizeof *t, compare_hash);

    size_t n;
    success = true;  /* We're successful unless we find a collision */
    unsigned collision_count = 0;
    for (n = 0; n+1 < bin_count; n++) {
        if (0 == memcmp( t[n].hash, t[n+1].hash, HASH_SIZE )) {
            success = false;   /* Darn!  Found a collision */
            collision_count++;
            if (!quiet_flag) {
                /* On a massive collision, don't flood the output */
                if (collision_count == 100) {
                     printf( "AND OTHER COLLISIONS NOT LISTED\n" );
                     break;
                }
                printf( "*** FOUND A COLLISION " );
                printf( "    (%d, %d, %d, %d, %d) vs (%d, %d, %d, %d, %d)\n",
                     t[n].d, t[n].key_num, t[n].sig_num, t[n].region, t[n].index,
                     t[n+1].d, t[n+1].key_num, t[n+1].sig_num, t[n+1].region, t[n+1].index );
            } else 
                break;  /* In quiet mode, there's no point in looking for */
                        /* a second collision */
        }
    }

failed:
    free(t); free(sig);
    return success;
}
