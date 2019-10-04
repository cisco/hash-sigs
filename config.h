#if !defined( CONFIG_H_ )
#define CONFIG_H_

/*
 * This file has #define's that specify how this package operates, and
 * are designed to be tweaked by the user.
 *
 * These can be adjusted to be appropriate for what the application and
 * the operating environment needs
 */

/*
 * These control how we do threading; these apply only if we have the
 * threading library installed
 *
 * This is the maximum number of threads we'll try to create; we won't
 * exceed this number no matter what the application tells us
 */
#define MAX_THREAD 16   /* Never try to create more than 16 threads */

/*
 * This is the number of threads we'll try to create if the application
 * doesn't specify otherwise (i.e. passes in 0)
 */
#define DEFAULT_THREAD 16 /* Go with 16 threads by default */

/*
 * We provide two different methods to be resiliant against fault attacks.
 * Both these methods have costs (but very different costs); if fault attacks
 * are a concern for your implementation, you should enable one (or both of
 * them if you're feeling especially paranoid, they are mutually compatible)
 */

/*
 * Method 1 for fault tolerance: when we initially compute the signature for
 * an internal root node, we store it (actually, the hash of the signed
 * public key) in the private key.  Then, if we ever need to compute that
 * signature again, we compare hashes; if they're different, then a fault
 * that could have leaked the private key has occurred
 * 0 -> We don't.
 * 1 -> We do.  This has the cost of expanding the size of the private key
 *      by 7*FAULT_CACHE_LEN bytes; it also can cause us to update the private
 *      key more often than expected (if you use reservations)
 */
#define FAULT_CACHE_SIG  1

/*
 * If we cache hashes of signatures (FAULT_CACHE_SIG), then this determines
 * the length of the hash we use; if FAULT_CACHE_LEN < 32, we truncate the
 * hash.  This is here because we generally don't need to store the entire
 * hash (unless we assume that the attacker can generate a precise fault at a
 * specific spot in the computation, and he has enough computational resources
 * to do a second preimage attack on a truncated hash), and shortening the
 * hash reduces the space used by a private key.
 */
#define FAULT_CACHE_LEN   8

/*
 * Method 2 for fault tolerance: compute hashes twice, and compare the results
 * Note that the goal of this is to prevent errors that would cause us
 * to leak information that would allow forgeries; errors that only cause us
 * to produce invalid signatures are not of concern.
 * 0 -> We don't.
 * 1 -> We do.  This has the extra cost of increassing load and signature
 *      generation times, and increased memory consumption
 */
#define FAULT_RECOMPUTE  0

/*
 * This modifies which seed generation logic we use
 * Note that changing these parameters will change the mapping
 * between private keys.
 *
 * 0 -> We generate seeds using the process defined in Appendix A of the draft
 *      This is slightly faster
 * 1 -> We use a side channel resistant process, never using any single secret
 *      seed in more than a defined number of distinct hashes
 * 2 -> We generate seeds and secrets in a way which is compatible with ACVP
 */
#define SECRET_METHOD 0

/*
 * If we're using the side channel resistant method, this defines the max
 * number of times we'll use a single secret.  Note that this is the log2
 * of the max number of times, and so 3 means 'no more than 8 times'
 * Reducing SECRET_MAX is a bit more costly; however I don't know that if
 * it is significant
 */
#define SECRET_MAX 4  /* Never use a seed more than 16 times */

/*
 * This determines whether we use the OpenSSL implementation of SHA-256
 * or we use our own
 * 1 -> We use the OpenSSL implementation; it's faster (and can use the
 *      Intel SHA256 instructions for even more speed)
 * 0 -> We use a portable C implementation; it's slower, but it does
 *      allow for some of the below instrumentation logic
 */
#define USE_OPENSSL 1   /* We use the OpenSSL implementation for SHA-256 */

/*
 * This determines whether we will print out the internal hash inputs and
 * outputs if the global hss_verbose is set.  Obvously, this is not great
 * for security; however it can be useful to track down those truly hard
 * bugs.  It is also quite chatty, and if you do use this, you probably
 * want to shut off multithreading
 * This works only if USE_OPENSSL == 0
 * 0 -> Omit debugging code
 * 1 -> Include debugging code
 */
#define ALLOW_VERBOSE 0  /* Don't do instrumentation */

/*
 * This determines whether we'll including some test instrumenetation into
 * the code.  This is never appropriate for a real application; this does
 * allow the testing code to run some additional tests
 * 0 -> Omit instrumentation
 * 1 -> Include instrumentation
 */
#define TEST_INSTRUMENTATION 0  /* Test mode off */

#endif /* CONFIG_H_ */
