
#include <stdio.h>
#include <stdlib.h>

#include "api.h"
#define CRYPTO_BYTES 4756

int main(void) {
  unsigned char sk[PRIVATE_KEY_LEN] = { 0 };
  unsigned char pk[HSS_MAX_PUBLIC_KEY_LEN] = { 0 };
  unsigned char message[17] = "This should work!";
  unsigned char signature[CRYPTO_BYTES + 17];
  unsigned long long length = 0;

  int key_gen_sign = keygen(sk, pk);
  printf("\nkeygen: %d\n", key_gen_sign);

	/*printf("private key:\n");
	for (unsigned long long j = 0; j < PRIVATE_KEY_LEN; j++) {
		printf("0x%x,", sk[j]);
	}

	printf("\npublic key:\n");
	for (unsigned long long j = 0; j < HSS_MAX_PUBLIC_KEY_LEN; j++) {
		printf("0x%x,", pk[j]);

	}*/
  printf("\n");
  int return_sign = sign(signature, &length, message, 17, sk);
  printf("return : %d\n", return_sign);
	/*printf("\nsign_loaded key:\n");
	for (unsigned long long j = 0; j < CRYPTO_BYTES; j++) {
		printf("%x,", signature[j]);
		if (j % 16 == 0) {
			printf("\n");
		}
		//signature[j] = 0x0;
	}
	printf("\n");*/

  int verification = verify(pk, signature, length, message, 17);
  printf("verification: %d\n",verification);
}

/*************************** End of file ****************************/
