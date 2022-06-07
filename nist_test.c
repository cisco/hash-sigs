#include "api.h"
#include <stdio.h>

void print_hex(unsigned char *a, int length, const char* string)
{
    printf("%s: \n", string);
    for (int i = 0; i < length; i++)
    {
        printf("%2x", a[i]);
    }
    printf("\n");
}

int main(void)
{
    // Keygen test
    int ret; 
    unsigned char pk[10000], sk[10000], sig[10000];
    unsigned pklen = 0, sklen = 0, siglen = 0, mlen = 0;
    ret = crypto_sign_keypair(pk, &pklen, sk, &sklen);

    printf("ret = %d\n", ret);
    print_hex(pk, pklen, "pk");
    print_hex(sk, sklen, "sk");

    // Signature test
    const unsigned char *m="this is a test from SandboxAQ\n";

    ret = crypto_sign(sig, &siglen, m, sizeof m, sk);
    printf("ret = %d\n", ret);
    print_hex(m, sizeof m, "message");
    print_hex(sig, siglen, "signature");

    // Verification test
    ret = crypto_sign_open(m, sizeof m, sig, siglen, pk);
    printf("ret = %d\n", ret);

    unsigned long remain = 0, max = 0; 
    crypto_remain_signatures(&remain, &max, sk);

    printf("remain = %d, max = %d\n", remain, max);

    return 0;
}