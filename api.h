#ifndef API_H
#define API_H

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign(unsigned char *sig, unsigned long *siglen,
                const unsigned char *m, unsigned long mlen, unsigned char *sk);

int crypto_sign_open(unsigned char *m, unsigned long *mlen,
                     const unsigned char *sm, unsigned long smlen, const unsigned char *pk);

int crypto_remain_signatures(unsigned long *remain,
                             unsigned long *max, unsigned char *sk);

#endif
