#include "api.h"
#include "params.h"
#include <stdio.h>

static void print_hex(const unsigned char *a, int length, const char *string)
{
    printf("%s[%d] = \n", string, length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x", a[i]);
    }
    printf("\n");
}

int main(void)
{
    // Keygen test
    int ret;
    unsigned char pk[CRYPTO_PUBLIC_KEY], sk[CRYPTO_SECRET_KEY], sig[CRYPTO_BYTES];
    unsigned long pklen = CRYPTO_PUBLIC_KEY, sklen = CRYPTO_SECRET_KEY, siglen = 0, mlen = 0;
    ret = crypto_sign_keypair(pk, sk);

    if (ret)
    {
        printf("    Unable to generate keypair\n");
        return 1;
    }
    print_hex(pk, pklen, "pk");
    print_hex(sk, sklen, "sk");

    // Signature test
    unsigned char m[] = "\nThis is a test from SandboxAQ\n";
    mlen = sizeof(m);
    ret = crypto_sign(sig, &siglen, m, mlen, sk);
    if (ret)
    {
        printf("    Unable to generate signature\n");
        return 1;
    }
    // print_hex(m, mlen, "message");
    // print_hex(sig, siglen, "signature");

    // Verification test
    ret = crypto_sign_open(m, &mlen, sig, siglen, pk);
    if (ret)
    {
        printf("    Signature NOT verified\n");
        return 1;
    }

    print_hex(sk, sklen, "sk");
    printf("siglen = %ld, mlen = %ld\n", siglen, mlen);

    // // Remaining signature test
    unsigned long remain = 0, max = 0;
    ret = crypto_remain_signatures(&remain, &max, sk);

    if (ret)
    {
        printf("    Unable to check remaining signature\n");
    }

    printf("remain = %ld, max = %ld\n", remain, max);

    return 0;
}