#if !defined( HSS_FAULT_H_ )
#define HSS_FAULT_H_

/*
 * This file defines the interface that we use to tell the hash
 * instrumentation why we're doing the hash.  The entire reason the
 * hash code cares is when we need to do fault testing
 *
 * That is, it is possible that a hash miscomputation might cause us
 * to sign two different messages with the same OTS; the whole point
 * of this exercise is to make sure, with FAULT_RECOMPUTE or FAULT_CACHE_SIG
 * on, this cannot happen
 *
 * This instrumentation code is able to introduce errors at fairly
 * precise places (e.g. the next level 1 OTS public key generation)
 * These are routines called by the LMS logic to tell the instrumentation
 * where we are
 *
 * Note: if this instrumentation is on, we probably don't want to use
 * threading (as this uses globals to communicate with the error injection
 * code)
 */

#include "config.h"

#if TEST_INSTRUMENTATION

/*
 * This informs the instrumentation that the next set of hashes will be done
 * on the given Merkle level (where 0 == top-most).  For those hashes outside
 * the hypertree, we just pass a 0
 */
void hss_set_level(int);

/*
 * These are the various reasons we do a hash.  Note that these categories
 * are assigned with the fault testing logic in mind; hashes that will give
 * the same basic result (e.g. initial message hash/ots signature generation
 * and summarization) are all in the same bin
 * ots_pkgen and ots_sign are in separate bins because we deliberately want
 * to trigger them separately
 */
enum hash_reason {
   h_reason_ots_pkgen,     /* Generating a OTS public key */
   h_reason_ots_sign,      /* Signing a message with an OTS private key */
                           /* also used for initial hash of the message */
                           /* and signature verification */
   h_reason_merkle,        /* Performing hashes within the Merkle tree */
   h_reason_derive,        /* Deriving OTS private keys */
   h_reason_derive_iseed,  /* Deriving I and seed values */
   h_reason_derive_c,      /* Deriving message randomizer */
   h_reason_priv_checksum, /* Computing a private key checksum */
   h_reason_sig_hash,      /* Computing a hash of a signature (for the */
                           /* CACHE_SIG logic) */
   h_reason_other          /* The miscilaneous category; aux file */
                           /* computations, root seed/I generation */
                           /* These are ones where a fault is unlikely */
                           /* to allow a forgery */
};

/*
 * This informs the instrumentation of the reason for the next set of hashes
 */
void hss_set_hash_reason(enum hash_reason);

#else

/*
 * If we aren't doing instrumentation, then null out the test calls
 */
#define hss_set_level(x)        ((void)0)
#define hss_set_hash_reason(x)  ((void)0)

#endif

#endif /* HSS_FAULT_H_ */
