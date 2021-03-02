/*
 * signatures.c
 *
 *  Created on: Jan 28, 2021
 *      Author: vader
 */

#include "api.h"
char *default_parm_set = "5/4,5/4";
//const char *default_parm_set = "20/8,10/8";
//const char *default_parm_set = "5/4,5/4";

const char *seedbits = 0;

#define DEFAULT_AUX_DATA 10916   /* Use 10+k of aux data (which works well */
/* with the above default parameter set) */

static const char *i_value = 0;
static bool convert_specified_seed_i_value(void*, size_t);

static int get_integer(const char **p) {
	int n = 0;

	while (isdigit(**p)) {
		n = 10 * n + **p - '0';
		*p += 1;
	}

	return n;
}

/*
 * This parses the parameter set; this is provided so we can try different
 * sets without recompiling the program each time.  This is placed here
 * because it's ugly parsing code that has nothing to do with how to use
 * HSS
 */
static int parse_parm_set(int *levels, param_set_t *lm_array,
		param_set_t *ots_array, size_t *aux_size, const char *parm_set) {
	int i;
	size_t aux = DEFAULT_AUX_DATA;
	for (i = 0;; i++) {
		if (i == 8) {
			//printf("Error: more than 8 HSS levels specified\n");
			return 0;
		}
		/* Get the number of levels of this tree */
		int h = get_integer(&parm_set);
		param_set_t lm;
		switch (h) {
		case 5:
			lm = LMS_SHA256_N32_H5;
			break;
		case 10:
			lm = LMS_SHA256_N32_H10;
			break;
		case 15:
			lm = LMS_SHA256_N32_H15;
			break;
		case 20:
			lm = LMS_SHA256_N32_H20;
			break;
		case 25:
			lm = LMS_SHA256_N32_H25;
			break;
		case 0:
			//printf("Error: expected height of Merkle tree\n");
			return 0;
		default:
			//printf("Error: unsupported Merkle tree height %d\n", h);
			//printf("Supported heights = 5, 10, 15, 20, 25\n");
			return 0;
		}
		/* Now see if we can get the Winternitz parameter */
		param_set_t ots = LMOTS_SHA256_N32_W8;
		if (*parm_set == '/') {
			parm_set++;
			int w = get_integer(&parm_set);
			switch (w) {
			case 1:
				ots = LMOTS_SHA256_N32_W1;
				break;
			case 2:
				ots = LMOTS_SHA256_N32_W2;
				break;
			case 4:
				ots = LMOTS_SHA256_N32_W4;
				break;
			case 8:
				ots = LMOTS_SHA256_N32_W8;
				break;
			case 0:
				//printf("Error: expected Winternitz parameter\n");
				return 0;
			default:
				//printf("Error: unsupported Winternitz parameter %d\n", w);
				//printf("Supported parmaeters = 1, 2, 4, 8\n");
				return 0;
			}
		}

		lm_array[i] = lm;
		ots_array[i] = ots;

		if (*parm_set == ':') {
			parm_set++;
			aux = get_integer(&parm_set);
			break;
		}
		if (*parm_set == '\0')
			break;
		if (*parm_set == ',') {
			parm_set++;
			continue;
		}
		//printf("Error: parse error after tree specification\n");
		return 0;
	}

	*levels = i + 1;
	*aux_size = aux;
	return 1;
}

/*
void list_parameter_set(int levels, const param_set_t *lm_array,
		const param_set_t *ots_array, size_t aux_size) {
	//printf("Parameter set being used: there are %d levels of Merkle trees\n",levels);
	int i;
	for (i = 0; i < levels; i++) {
		//printf("Level %d: hash function = SHA-256; ", i);
		int h = 0;
		switch (lm_array[i]) {
		case LMS_SHA256_N32_H5:
			h = 5;
			break;
		case LMS_SHA256_N32_H10:
			h = 10;
			break;
		case LMS_SHA256_N32_H15:
			h = 15;
			break;
		case LMS_SHA256_N32_H20:
			h = 20;
			break;
		case LMS_SHA256_N32_H25:
			h = 25;
			break;
		}
		//printf("%d level Merkle tree; ", h);
		int w = 0;
		switch (ots_array[i]) {
		case LMOTS_SHA256_N32_W1:
			w = 1;
			break;
		case LMOTS_SHA256_N32_W2:
			w = 2;
			break;
		case LMOTS_SHA256_N32_W4:
			w = 4;
			break;
		case LMOTS_SHA256_N32_W8:
			w = 8;
			break;
		}
		//printf("Winternitz param %d\n", w);
	}
	if (aux_size > 0) {
		printf("Maximum of %lu bytes of aux data\n", (unsigned long) aux_size);
	} else {
		printf("Aux data disabled\n");
	}
}
*/

const char* check_prefix(const char *s, const char *prefix) {
	while (*prefix) {
		if (*s++ != *prefix++)
			return 0;
	}
	return s;
}

int fromhex(char c) {
	if (isdigit(c))
		return c - '0';
	switch (c) {
	case 'a':
	case 'A':
		return 10;
	case 'b':
	case 'B':
		return 11;
	case 'c':
	case 'C':
		return 12;
	case 'd':
	case 'D':
		return 13;
	case 'e':
	case 'E':
		return 14;
	case 'f':
	case 'F':
		return 15;
	default:
		return 0; /* Turn any nonhexdigit into a 0 */
	}
}

/*
 * This is used if the user maually specified the seed and the
 * i values
 * This converts what the user specified into the format that
 * the library expects
 */
static bool convert_specified_seed_i_value(void *buffer, size_t len) {
	int i;
	const char *in = seedbits;
	unsigned char *out = buffer;
	for (i = 0; i < len; i++) {
		/* After 32 bytes of seed, then comes the i value */
		if (i == 32) {
			in = i_value;
		}
		int c = fromhex(*in);
		if (*in)
			in++;
		int d = fromhex(*in);
		if (*in)
			in++;
		*out++ = 16 * c + d;
	}

	return true;
}

int parse_parm_set(int *levels, param_set_t *lm_array, param_set_t *ots_array,
		size_t *aux_size, const char *parm_set);
/*
void list_parameter_set(int levels, const param_set_t *lm_array,
		const param_set_t *ots_array, size_t aux_size);
*/

/*
 * This is a function that is supposed to generate truly random values.
 * This is a hideous version of this; this needs to be replaced by something
 * secure in a real product
 */

bool do_rand(void *output, size_t len) {
	if (seedbits) {
		/* The seed was specified on the command line */
		/* Return that exact seed and i */
		/* This is not something a real application should do */
		return convert_specified_seed_i_value(output, len);
	}
	struct {
		unsigned char dev_random_output[32];
		int rand_output[16];
		/* Potentially more random sources here */
		unsigned count;
	} buffer;
	int i;

	static int set_seed = 0;
	if (!set_seed) {
                srand();
		set_seed = 1;
	}
	for (i = 0; i < 16; i++) {
		buffer.rand_output[i] = rand();
	}

	/* If we had more random sources, we'd sample them here */

	unsigned output_buffer[32];
	for (i = 0; len > 0; i++) {
		buffer.count = i;

		/* Ok, hash all our random samples together to generate the random */
		/* string that was asked for */
		hss_hash(output_buffer, HASH_SHA256, &buffer, sizeof buffer);

		/* Copy that hash to the output buffer */
		int this_len = 32;
		if (this_len > len)
			this_len = len;
		memcpy(output, output_buffer, this_len);

		/* Advance pointers */
		output = (unsigned char*) output + this_len;
		len -= this_len;
	}

	/* Clean up after ourselves.  Yes, this is a demo program; doesn't mean */
	/* we get to be sloppy */
	hss_zeroize(output_buffer, sizeof output_buffer);
	hss_zeroize(&buffer, sizeof buffer);

	return true;
}

int keygen(unsigned char *sk, unsigned char *pk) {

	/* Parse the parameter set */
	int levels;
	char *parm_set = 0;
	param_set_t lm_array[MAX_HSS_LEVELS];
	param_set_t ots_array[MAX_HSS_LEVELS];
	size_t aux_size;
	char *private_key_filename = "";

	if (!parm_set) {
		parm_set = default_parm_set;
	}
	if (!parse_parm_set(&levels, lm_array, ots_array, &aux_size, parm_set)) {
		return 0;
	}

	/* Tell the user how we interpreted the parameter set he gave us */
	//list_parameter_set(levels, lm_array, ots_array, aux_size);

	/* We'll place the public key in this array */
	unsigned len_public_key = hss_get_public_key_len(levels, lm_array,
			ots_array);
	if (len_public_key == 0) {
		//free(private_key_filename);
		return 0;
	}
	unsigned char public_key[HSS_MAX_PUBLIC_KEY_LEN];

	/* And we'll place the aux data in this array */
	unsigned aux_len;
	if (aux_size > 0) {
		aux_len = hss_get_aux_data_len(aux_size, levels, lm_array, ots_array);
		//printf("aux_len = %d\n", aux_len);
	} else {
		aux_len = 1;
	}
	unsigned char *aux = malloc(aux_len);
	if (!aux) {
		//printf("error mallocing aux; not generating aux\n");
		aux_len = 0;
		aux = 0;
	}

	//printf("Generating public key %s (will take a while)\n",	private_key_filename);
	if (!hss_generate_private_key(do_rand, /* Routine to generate randomness */
	levels, /* # of Merkle levels */
	lm_array, ots_array, /* The LM and OTS parameters */
	sk, private_key_filename, /* Routine to write out */
	/* the genearted private key */
	public_key, len_public_key, /* The public key is placed here */
	aux_size > 0 ? aux : 0, aux_len, /* Where to place the aux data */
	0)) { /* Use the defaults for extra info */
		free(private_key_filename);
		free(aux);
		return 0;
	}
	//free(private_key_filename);
	private_key_filename = 0;

	memcpy(pk, &public_key, sizeof(unsigned char) * len_public_key);

	/* If the key was specified manually, put in our warning
	 if (seedbits) {
	 fprintf( stderr, "*** Warning: the key was not generated manually\n"
	 "    This key should not be used for real security\n");
	 }
	 */
	free(aux);
	free(private_key_filename);

	return 1;
}

int verify(unsigned char *pk, unsigned char *sig, size_t sig_len,
		unsigned char *m, size_t mlen) {
	/* Step 1: read in the public key */

	struct hss_validate_inc ctx;
	(void) hss_validate_signature_init(&ctx, /* Incremental validate context */
	pk, /* Public key */
	sig, sig_len, /* Signature */
	0); /* Use the defaults for extra info */

	(void) hss_validate_signature_update(&ctx, /* Incremental validate context */
	m, /* Next piece of the message */
	mlen); /* Length of this piece */

	bool status = hss_validate_signature_finalize(&ctx, /* Incremental validate context */
	sig, /* Signature */
	0); /* Use the defaults for extra info */
	/*if (status) {
		printf("    Signature verified\n");
	} else {
		printf("    Signature NOT verified\n");
	}*/

	return status;
}

int sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
		unsigned long long mlen, unsigned char *private_key) {


	/* Read in the auxilliary file */

	int levels;
	param_set_t lm_array[MAX_HSS_LEVELS];
	param_set_t ots_array[MAX_HSS_LEVELS];
	size_t aux_size;
	char *default_parm_set = "5/4,5/4";
	const char *parm_set = default_parm_set;
	if (!parse_parm_set(&levels, lm_array, ots_array, &aux_size, parm_set)) {
		return 0;
	}

	unsigned aux_len;
	if (aux_size > 0) {
		aux_len = hss_get_aux_data_len(aux_size, levels, lm_array, ots_array);
		//printf("aux_len = %d\n", aux_len);
	} else {
		aux_len = 1;
	}
	//unsigned char *aux = malloc(aux_len);
	unsigned char aux[aux_len];

	size_t len_aux_data = aux_len;
	void *aux_data = aux;
	/* Load the working key into memory */
	//printf("Loading private key\n");
	//fflush(stdout);
	struct hss_working_key *w = hss_load_private_key(private_key, /* How to load the */
	/* private key */
	0, 0, /* Use minimal memory */
	aux_data, len_aux_data, /* The auxiliary data */
	0); /* Use the defaults for extra info */
	if (!w) {
		//printf("Error loading private key\n");
		free(aux_data);
		hss_free_working_key(w);
		return 0;
	}
	//free(aux_data);

	//printf("Loaded private key\n"); /* printf here mostly so the user */
	//fflush(stdout); /* gets a feel for how long this step took */
	/* compared to the signing steps below */

	/* Now, go through the file list, and generate the signatures for each */

	/* Look up the signature length */
	size_t sig_len;
	sig_len = hss_get_signature_len_from_working_key(w);
	if (sig_len == 0) {
		//printf("Error getting signature len\n");
		hss_free_working_key(w);
		return 0;
	}

	/*unsigned char *sig = malloc(sig_len);
	 if (!sig) {
	 printf("Error during malloc\n");
	 hss_free_working_key(w);
	 return 0;
	 }*/

	/*
	 * Read the file in, and generate the signature.  We don't want to
	 * assume that we can fit the entire file into memory, and so we
	 * read it in in pieces, and use the API that allows us to sign
	 * the message when given in pieces
	 */
	char *private_key_filename = "";
	struct hss_sign_inc ctx;
	(void) hss_sign_init(&ctx, /* Incremental signing context */
	w, /* Working key */
	private_key, /* Routine to update the */
	private_key_filename, /* private key */
	sm, (size_t) smlen, /* Where to place the signature */
	0); /* Use the defaults for extra info */

	(void) hss_sign_update(&ctx, /* Incremental signing context */
	m, /* Next piece of the message */
	mlen); /* Length of this piece */

	bool status = hss_sign_finalize(&ctx, /* Incremental signing context */
	w, /* Working key */
	sm, /* Signature */
	0); /* Use the defaults for extra info */

	/*if (!status) {
		printf("    Unable to generate signature\n");
	}*/

	if (sig_len == 0) {
		return 0;
	}
	memcpy(smlen, &sig_len, sizeof(size_t));
	hss_free_working_key(w);
	//free(sig);
	return status;
}

