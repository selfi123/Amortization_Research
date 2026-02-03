/**
 * crypto_core.h
 * Core Cryptographic Functions for Post-Quantum IoT Security
 * Implements LR-IoTA (Ring-LWE) and QC-LDPC Hybrid Encryption
 */

#ifndef CRYPTO_CORE_H_
#define CRYPTO_CORE_H_

#include <stdint.h> 
#include <string.h>

/* ========== GLOBAL PARAMETERS (Table 2 from paper) ========== */

#define POLY_DEGREE 512                    // n: Polynomial degree
#define MODULUS_Q 536870909L               // q: 2^29 - 3
#define STD_DEVIATION 43                   // σ: Standard deviation
#define BOUND_E 2097151L                   // E: 2^21 - 1
#define RING_SIZE 3                        // N: Number of ring members

/* --- ADD THESE MISSING LINES --- */
#define REJECT_M 20000                     // M: Rejection constant (User Requested)
#define REJECT_V 10000                     // V: Uniformity bound (User Requested)
#define OMEGA 18                           // w: Weight parameter
/* ------------------------------- */

/* LDPC Parameters */
#define LDPC_ROWS 408                      // X: Number of rows
#define LDPC_COLS 816                      // Y: Number of columns
#define LDPC_ROW_WEIGHT 6                  // Row weight
#define LDPC_COL_WEIGHT 3                  // Column weight
#define LDPC_N0 4                          // Number of circulant matrices

/* Crypto primitives */
#define SHA256_DIGEST_SIZE 32
#define AES128_KEY_SIZE 16
#define AES128_BLOCK_SIZE 16

/* Other constants */
#define KEYWORD_SIZE 32
#define MESSAGE_MAX_SIZE 64

/* ========== SESSION AMORTIZATION PARAMETERS ========== */

/* Session parameters */
#define SID_LEN 8
#define MASTER_KEY_LEN 32
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN 16
#define MAX_MESSAGES_PER_SESSION 10000
#define RATCHET_INTERVAL 500
#define DEFAULT_SESSION_LIFETIME 3600  /* seconds */
#define MAX_SESSIONS 16  /* Gateway limit */


/* ========== DATA STRUCTURES ========== */

/* Polynomial representation for Ring-LWE */
typedef struct {
    int32_t coeff[POLY_DEGREE];
} Poly512;

/* Ring-LWE Key Pair */
typedef struct {
    Poly512 secret;      // sk
    Poly512 public;      // pk
    Poly512 random;      // R
} RingLWEKeyPair;

/* Ring Signature (for N=3 members) */
typedef struct {
    Poly512 S[RING_SIZE];    // Signature components S1, S2, S3
    uint8_t keyword[KEYWORD_SIZE];
    uint8_t challenge_hash[SHA256_DIGEST_SIZE];  // Store challenge hash for verification
} RingSignature;

/* LDPC Key structures (compressed representation) */
typedef struct {
    uint8_t seed[32];              // Seed for matrix generation
    uint16_t shift_indices[LDPC_N0]; // Circulant shift indices
} LDPCPublicKey;

typedef struct {
    LDPCPublicKey public_part;
    uint8_t private_info[64];      // LU decomposition info
} LDPCKeyPair;

/* Error vector for LDPC encoding */
typedef struct {
    uint8_t bits[LDPC_COLS / 8];   // Packed bit representation
    uint16_t hamming_weight;
} ErrorVector;

/* Session encryption context (old - for backward compatibility) */
typedef struct {
    uint8_t session_key[AES128_KEY_SIZE];
    uint8_t iv[AES128_BLOCK_SIZE];
} SessionContext;

/* ========== SESSION AMORTIZATION STRUCTURES ========== */

/* Sender session context */
typedef struct {
    uint8_t sid[SID_LEN];
    uint8_t K_master[MASTER_KEY_LEN];
    uint32_t counter;
    uint32_t expiry_ts;
    uint8_t active;
} session_ctx_t;

/* Gateway session entry */
typedef struct {
    uint8_t sid[SID_LEN];
    uint8_t K_master[MASTER_KEY_LEN];
    uint32_t last_seq;
    uint32_t expiry_ts;
    uint8_t peer_addr[16];  /* IPv6 address */
    uint8_t in_use;
} session_entry_t;


/* ========== POLYNOMIAL OPERATIONS ========== */

/**
 * Bernstein Reconstruction (Recursive Karatsuba) - Algorithm 3
 * Multiply two polynomials using recursive splitting
 * @param result: Output polynomial (degree 2n-1)
 * @param a: First input polynomial
 * @param b: Second input polynomial
 * @param degree: Degree of input polynomials
 * @param scratch: Temporary buffer for recursion (size needs to be sufficient)
 */
void poly_mul_bernstein(int32_t *result, const int32_t *a, const int32_t *b, int degree, int32_t *scratch);

/**
 * Modular reduction: result = a mod q
 */
void poly_mod_q(Poly512 *result, const Poly512 *a);

/**
 * Polynomial addition: result = a + b mod q
 */
void poly_add(Poly512 *result, const Poly512 *a, const Poly512 *b);

/**
 * Polynomial subtraction: result = a - b mod q
 */
void poly_sub(Poly512 *result, const Poly512 *a, const Poly512 *b);

/**
 * Scalar multiplication: result = scalar * a mod q
 */
void poly_scalar_mul(Poly512 *result, int32_t scalar, const Poly512 *a);

/**
 * Compute L2 norm of polynomial
 */
uint32_t poly_norm(const Poly512 *a);

/* ========== RANDOM NUMBER GENERATION ========== */

/**
 * Initialize PRNG with seed
 */
void crypto_prng_init(uint32_t seed);

/**
 * Generate random 32-bit integer
 */
uint32_t crypto_random_uint32(void);

/**
 * Discrete Gaussian sampling (Box-Muller approximation)
 * @param sigma: Standard deviation
 * @return: Sample from discrete Gaussian distribution
 */
int32_t gaussian_sample(int sigma);

/* ========== RING-LWE OPERATIONS ========== */

/**
 * Ring-LWE Key Generation with rejection sampling
 * Implements Algorithm 1 from paper
 */
int ring_lwe_keygen(RingLWEKeyPair *keypair);

/**
 * Generate Ring Signature (N=3 members)
 * Implements Algorithm 3 - Signature Generation
 * @param sig: Output signature
 * @param keyword: Keyword to sign
 * @param signer_keypair: Signer's key pair
 * @param other_pubkeys: Public keys of other N-1 ring members
 * @param signer_index: Index of signer in ring (0-2)
 */
int ring_sign(RingSignature *sig, const uint8_t *keyword,
              const RingLWEKeyPair *signer_keypair,
              const Poly512 other_pubkeys[RING_SIZE-1],
              int signer_index);

/**
 * Verify Ring Signature
 * Implements Algorithm 4 - Signature Verification
 */
int ring_verify(const RingSignature *sig, const Poly512 public_keys[RING_SIZE]);

/* ========== QC-LDPC OPERATIONS ========== */

/**
 * Generate QC-LDPC key pair
 * Implements diagonally structured LDPC with column-wise loop optimization
 */
int ldpc_keygen(LDPCKeyPair *keypair);

/**
 * Encode error vector to syndrome
 * syndrome = H * e^T
 */
void ldpc_encode(uint8_t *syndrome, const ErrorVector *error, const LDPCPublicKey *pubkey);

/**
 * SLDSPA Decoder - Algorithm 6
 * Simplified Log Domain Sum-Product Algorithm with Min-Sum approximation
 * @param error: Output recovered error vector
 * @param syndrome: Input syndrome
 * @param keypair: LDPC key pair
 * @return: 0 on success, -1 on failure
 */
int sldspa_decode(ErrorVector *error, const uint8_t *syndrome, const LDPCKeyPair *keypair);

/**
 * Generate random low-weight error vector
 */
void generate_error_vector(ErrorVector *error, uint16_t target_weight);

/* ========== CRYPTOGRAPHIC HASH ========== */

/**
 * SHA-256 hash function
 * @param output: 32-byte output buffer
 * @param input: Input data
 * @param len: Length of input data
 */
void sha256_hash(uint8_t output[SHA256_DIGEST_SIZE], const uint8_t *input, uint32_t len);

/**
 * Hash polynomial for challenge generation
 */
void hash_poly_challenge(uint8_t output[SHA256_DIGEST_SIZE], const Poly512 polys[], int count);

/* ========== AES ENCRYPTION ========== */

/**
 * AES-128 key expansion
 */
void aes128_key_expansion(uint8_t *roundkeys, const uint8_t *key);

/**
 * AES-128 encryption (single block)
 */
void aes128_encrypt_block(uint8_t *output, const uint8_t *input, const uint8_t *roundkeys);

/**
 * AES-128 decryption (single block)
 */
void aes128_decrypt_block(uint8_t *output, const uint8_t *input, const uint8_t *roundkeys);

/**
 * AES-128 CTR mode encryption/decryption
 */
void aes128_ctr_crypt(uint8_t *output, const uint8_t *input, uint32_t len,
                      const uint8_t *key, const uint8_t *iv);

/* ========== HYBRID ENCRYPTION WRAPPER ========== */

/**
 * Derive session key from error vector using SHA-256
 */
void derive_session_key(SessionContext *ctx, const ErrorVector *error);

/**
 * Hybrid encrypt: LDPC + AES
 */
int hybrid_encrypt(uint8_t *ciphertext, uint32_t *cipher_len,
                   const uint8_t *plaintext, uint32_t plain_len,
                   const LDPCPublicKey *pubkey,
                   uint8_t *syndrome_out);

/**
 * Hybrid decrypt: LDPC + AES
 */
int hybrid_decrypt(uint8_t *plaintext, uint32_t *plain_len,
                   const uint8_t *ciphertext, uint32_t cipher_len,
                   const uint8_t *syndrome,
                   const LDPCKeyPair *keypair);

/* ========== UTILITY FUNCTIONS ========== */

/**
 * Constant-time comparison
 */
int constant_time_compare(const uint8_t *a, const uint8_t *b, uint32_t len);

/**
 * Print polynomial (for debugging)
 */
void poly_print(const char *label, const Poly512 *p, int num_coeffs);

/* ========== SESSION AMORTIZATION FUNCTIONS ========== */

/**
 * Secure memory zeroization (compiler cannot optimize out)
 */
void secure_zero(void *ptr, size_t len);

/**
 * Cryptographically secure random number generator
 */
void crypto_secure_random(uint8_t *output, size_t len);

/**
 * HMAC-SHA256 implementation
 */
void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len);

/**
 * HKDF-SHA256 key derivation (RFC 5869)
 */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/**
 * AEAD Encryption (AES-128-CTR + HMAC-SHA256)
 */
int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce);

/**
 * AEAD Decryption (AES-128-CTR + HMAC-SHA256)
 */
int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce);

/**
 * Derive master session key from error vector and gateway nonce
 * K_master = HKDF(salt=NULL, IKM=error||N_G, info="master-key")
 */
void derive_master_key(uint8_t *K_master,
                      const uint8_t *error, size_t err_len,
                      const uint8_t *gateway_nonce, size_t nonce_len);

/**
 * Session encryption with HKDF + AEAD
 */
int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len);

/**
 * Session decryption with HKDF + AEAD (includes replay protection)
 */
int session_decrypt(session_entry_t *se, uint32_t counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len);

/**
 * Key ratcheting (future work)
 */
void ratchet_master(session_ctx_t *ctx, const uint8_t *nonce, size_t nonce_len);

#endif /* CRYPTO_CORE_H_ */

