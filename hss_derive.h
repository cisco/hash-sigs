#include "common_defs.h"

/*
 * This defines what seed generation logic we use
 * Note that changing these parameters will change the mapping
 * between private keys.
 *
 * 0 -> We generate seeds using the process defined in Appendix A of the draft
 * 1 -> We use a side channel resistant process, never using any single secret
 *      seed in more than a defined number of distinct hashes
 */
#define SECRET_METHOD 1

/*
 * If we're using the side channel resistant method, this defines the max
 * number of times we'll use a single secret.  Note that this is the log2
 * of the max number of times, and so 3 means 'no more than 8 times'
 */
#define SECRET_MAX 4  /* Never use a seed more than 16 times */

#if SECRET_MAX > 31
#error The code is not designed for a SECRET_MAX that high
#endif
#define SECRET_MAX_MASK (((merkle_index_t)1 << SECRET_MAX) - 1)

struct seed_derive {
    const unsigned char *I;
    const unsigned char *master_seed;
    merkle_index_t q;
    unsigned j;

#if SECRET_METHOD == 1
    unsigned q_levels, j_levels;
    merkle_index_t r_mask;
    unsigned j_mask;
#define MAX_Q_HEIGHT ((MAX_MERKLE_HEIGHT + SECRET_MAX - 1) / SECRET_MAX)
#define MAX_J_HEIGHT ((                9 + SECRET_MAX - 1) / SECRET_MAX)
        /* '9' is the number of bits a maximum 'p' can take up */

    unsigned j_value[MAX_J_HEIGHT];  /* these are the values we insert */
        /* into the hash.  The lower SECRET_MAX bits are which child of */
        /* the parent it is; the higher bits indicate the parents' */
        /* identities */

    unsigned char q_seed[MAX_Q_HEIGHT][SEED_LEN];
    unsigned char j_seed[MAX_Q_HEIGHT][SEED_LEN];
#endif
};

bool hss_seed_derive_init( struct seed_derive *derive,
                 param_set_t lm, param_set_t ots,
                 const unsigned char *I, const unsigned char *seed );

/* This sets the internal 'q' value */
/* If we've already have a 'q' value set, it'll try to minimize the number */
/* of hashes done */
/* Once you've done that, you'll need to reset the 'h' */
void hss_seed_derive_set_q( struct seed_derive *derive, merkle_index_t q );

/* This sets the internal 'j' value */
void hss_seed_derive_set_j( struct seed_derive *derive, unsigned j );

#define NUM_ARTIFICIAL_SEEDS    3  /* 3 seeds are listed below */
    /* These are the j values used when we're deriving the I/seed values */
    /* for child Merkle trees */
#define SEED_CHILD_SEED         (~1)
#define SEED_CHILD_I            (SEED_CHILD_SEED + 1)
    /* This is the j value used when we're asking for the randomizer C */
    /* for signing a message */
#define SEED_RANDOMIZER_INDEX   (~2)

/* This generates the current seed.  If increment_j is set, this will set */
/* up for the next j value */
void hss_seed_derive( unsigned char *seed, struct seed_derive *derive,
                      bool increment_j );

/* This needs to be called when we done with a seed_derive */
/* That structure contains keying data, this makes sure those are cleaned */
void hss_seed_derive_done( struct seed_derive *derive );


