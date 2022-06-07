#include <oqs/rand.h>
#include "api.h"
#include "hss.h"
#include "hss_verify.h"
#include "params.h"

/*************************************************
* Name:        LMS_crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of LMS_CRYPTO_PUBLICKEYBYTES bytes)
*              - size_t *pklen: pointer to public key length (0 if failed)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of LMS_CRYPTO_SECRETKEYBYTES bytes)
*              - size_t *sklen: pointer to private key length (0 if failed)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(unsigned char *pk, size_t *pklen,
                        unsigned char *sk, size_t *sklen)
{
    uint8_t buf[48];
    /* Select NIST KAT as random generator*/
    if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        return OQS_ERROR;
    }

    /* Initialize NIST KAT, this time it reads from /dev/urandom */
    OQS_randombytes(buf, 48);
    OQS_randombytes_nist_kat_init_256bit(buf, NULL);

#if NIST_LEVEL == 1
    param_set_t lm_type[]  = {PARAM_LM_HEIGHT};
    param_set_t ots_type[] = {PARAM_OTS_WIDTH};
#else 
    param_set_t lm_type[]  = {PARAM_LM_HEIGHT0, PARAM_LM_HEIGHT1};
    param_set_t ots_type[] = {PARAM_OTS_WIDTH , PARAM_OTS_WIDTH};
#endif
    unsigned levels = PARAM_LEVEL;
    /* Generate keypair using LMS API */

    /* Maximum size of aux data for optimal performance */
    const size_t aux_data_max_length = 4096 * 10;
    size_t aux_data_len = hss_get_aux_data_len(aux_data_max_length, levels, lm_type, ots_type);
    unsigned char *aux_data = malloc(aux_data_len);
    
    size_t pubkey_size = hss_get_public_key_len(levels, lm_type, ots_type);
    size_t privkey_size = hss_get_private_key_len(levels, lm_type, ots_type);
    bool success = hss_generate_private_key(OQS_randombytes, levels, lm_type, ots_type,
                             NULL, sk, pk, pubkey_size, aux_data, aux_data_len, 0);

    /* Branchless if-else magic */
    *pklen = (-success) & (pubkey_size);
    *sklen = (-success) & (privkey_size);

    free(aux_data);
    if (!success)
    {
        printf( "Error generating keypair\n" );
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

/* 
 * Sign a message
 */
int crypto_sign(unsigned char *sig, size_t *siglen,
                const unsigned char *m, size_t mlen, const unsigned char *sk)
{
    unsigned char aux_data[10240];
    struct hss_working_key *working_key = hss_load_private_key(NULL, sk, 
                                100000, aux_data, sizeof aux_data, 0);
    
    if (!working_key) {
        printf( "Error loading working key\n" );
        return OQS_ERROR;
    }

    bool success = hss_generate_signature(working_key, NULL, NULL, m, mlen, sig, *siglen, 0);
     
    hss_free_working_key(working_key);

    if (!success)
    {
        printf( "Error generating signature\n" );
        return OQS_ERROR;
    }

    return OQS_SUCCESS;
}

/* 
 * Verify a signed message
 */
int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen, const unsigned char *pk)
{
    bool success = hss_validate_signature(pk, m, *mlen, sm, smlen, 0);

    if (!success)
    {
        return OQS_ERROR;
    }
    return OQS_SUCCESS;
}

/* 
 * Return the number of remaining signatures and maximum possibile signatures
 * The total number of used signatures can be the result of remaining and maximu. 
 * Input is secrect key. 
 * 
 */
int crypto_remain_signatures(unsigned long *remain,
                             unsigned long *max, unsigned char *sk)
{
    unsigned char aux_data[10240];
    struct hss_working_key *w = hss_load_private_key(NULL, sk, 
                                100000, aux_data, sizeof aux_data, 0);
    
    if (!w) {
        printf( "Error loading working key\n" );
        return OQS_ERROR;
    }
    *remain = w->reserve_count; 
    *max = w->max_count;

    hss_free_working_key(w);
    return OQS_SUCCESS;
}
