#ifndef API_H
#define API_H

int crypto_sign_keypair(unsigned char *pk, size_t *pklen,
                        unsigned char *sk, size_t *sklen);

int crypto_sign(unsigned char *sig, size_t *siglen,
                const unsigned char *m, size_t mlen, const unsigned char *sk);

int crypto_sign_open(unsigned char *m, size_t *mlen,
                     const unsigned char *sm, size_t smlen, const unsigned char *pk);

int crypto_remain_signatures(unsigned long *remain,
                             unsigned long *max, unsigned char *sk);

#endif
