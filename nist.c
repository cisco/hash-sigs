#include <oqs/rand.h>
#include "api.h"
#include "hss.h"
#include "params.h"

/*************************************************
* Name:        LMS_crypto_sign_keypair
*
* Description: Generates public and private key.
*
* Arguments:   - uint8_t *pk: pointer to output public key (allocated
*                             array of LMS_CRYPTO_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key (allocated
*                             array of LMS_CRYPTO_SECRETKEYBYTES bytes)
*
* Returns 0 (success)
**************************************************/
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk)
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
    
    int pubkey_size = hss_get_public_key_len(levels, lm_type, ots_type);
    int privkey_size = hss_get_private_key_len(levels, lm_type, ots_type);
    
    hss_generate_private_key(OQS_randombytes, levels, lm_type, ots_type,
                             NULL, sk, pk, pubkey_size, aux_data, aux_data_len, NULL);

    free(aux_data);

    return OQS_SUCCESS;
}


int crypto_sign(uint8_t *sig, size_t *siglen,
                const uint8_t *m, size_t mlen, const uint8_t *sk)
{
}

int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen, const uint8_t *pk)
{
}
