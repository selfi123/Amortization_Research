/**
 * crypto_core_session.c
 * Session Amortization Cryptographic Primitives
 * Implements HMAC-SHA256, HKDF, AEAD, and session key derivation
 */

#include "crypto_core.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* ========== SECURE MEMORY OPERATIONS ========== */

/**
 * Secure memory zeroization - compiler cannot optimize this out
 */
void secure_zero(void *ptr, size_t len) {
#if defined(__STDC_LIB_EXT1__) || defined(__GLIBC__)
    /* Use explicit_bzero if available */
    explicit_bzero(ptr, len);
#else
    /* Volatile pointer prevents optimization */
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) {
        *p++ = 0;
    }
#endif
}

/* ========== CRYPTOGRAPHICALLY SECURE RNG ========== */

/**
 * Platform-specific secure random number generator
 */
void crypto_secure_random(uint8_t *output, size_t len) {
#ifdef CONTIKI
    /* Use Contiki's hardware RNG if available */
    /* Note: #include "dev/random.h" must be added for Contiki builds */
    size_t i;
    for (i = 0; i < len; i++) {
        /* random_rand() is provided by Contiki */
        output[i] = rand() & 0xFF;  /* Use rand() for now */
    }
#else
    /* Native/test: use /dev/urandom or rand() fallback */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(output, 1, len, f);
        fclose(f);
    } else {
        /* Fallback: use standard rand() - NOT SECURE FOR PRODUCTION! */
        size_t i;
        for (i = 0; i < len; i++) {
            output[i] = rand() & 0xFF;
        }
    }
#endif
}

/* ========== HMAC-SHA256 IMPLEMENTATION ========== */

/**
 * HMAC-SHA256 implementation
 * RFC 2104: HMAC = H((K ⊕ opad) || H((K ⊕ ipad) || message))
 */
void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len) {
    uint8_t k_pad[64];  /* SHA-256 block size */
    uint8_t i_key_pad[64], o_key_pad[64];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    uint8_t *inner_msg;
    uint8_t outer_msg[64 + SHA256_DIGEST_SIZE];
    size_t i;
    
    /* Key padding: if key > 64 bytes, hash it first */
    memset(k_pad, 0, 64);
    if (key_len > 64) {
        sha256_hash(k_pad, key, key_len);
    } else {
        memcpy(k_pad, key, key_len);
    }
    
    /* Create inner and outer pads */
    for (i = 0; i < 64; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5c;
    }
    
    /* Inner hash: H(K ⊕ ipad || message) */
    inner_msg = (uint8_t *)malloc(64 + msg_len);
    if (!inner_msg) {
        /* Fallback for embedded systems without malloc */
        return;
    }
    
    memcpy(inner_msg, i_key_pad, 64);
    memcpy(inner_msg + 64, msg, msg_len);
    sha256_hash(inner_hash, inner_msg, 64 + msg_len);
    free(inner_msg);
    
    /* Outer hash: H(K ⊕ opad || inner_hash) */
    memcpy(outer_msg, o_key_pad, 64);
    memcpy(outer_msg + 64, inner_hash, SHA256_DIGEST_SIZE);
    sha256_hash(output, outer_msg, 64 + SHA256_DIGEST_SIZE);
    
    /* Zeroize sensitive data */
    secure_zero(k_pad, 64);
    secure_zero(i_key_pad, 64);
    secure_zero(o_key_pad, 64);
    secure_zero(inner_hash, SHA256_DIGEST_SIZE);
}

/* ========== HKDF-SHA256 IMPLEMENTATION ========== */

/**
 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
 * RFC 5869 Section 2.2
 */
static void hkdf_extract(uint8_t *prk,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len) {
    if (salt == NULL || salt_len == 0) {
        /* Use zero-filled salt if none provided */
        uint8_t zero_salt[SHA256_DIGEST_SIZE];
        memset(zero_salt, 0, SHA256_DIGEST_SIZE);
        hmac_sha256(prk, zero_salt, SHA256_DIGEST_SIZE, ikm, ikm_len);
    } else {
        hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
    }
}

/**
 * HKDF-Expand: OKM = T(1) || T(2) || ... || T(N)
 * where T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
 * RFC 5869 Section 2.3
 */
static void hkdf_expand(uint8_t *okm, size_t okm_len,
                       const uint8_t *prk,
                       const uint8_t *info, size_t info_len) {
    uint8_t n = (okm_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint8_t t[SHA256_DIGEST_SIZE];
    uint8_t *hmac_input;
    size_t okm_offset = 0;
    uint8_t i;
    size_t input_len;
    size_t to_copy;
    
    memset(t, 0, SHA256_DIGEST_SIZE);
    
    hmac_input = (uint8_t *)malloc(SHA256_DIGEST_SIZE + info_len + 1);
    if (!hmac_input) {
        return;  /* Allocation failure */
    }
    
    for (i = 1; i <= n; i++) {
        input_len = 0;
        
        /* T(i-1) (empty for first iteration) */
        if (i > 1) {
            memcpy(hmac_input, t, SHA256_DIGEST_SIZE);
            input_len = SHA256_DIGEST_SIZE;
        }
        
        /* info */
        if (info && info_len > 0) {
            memcpy(hmac_input + input_len, info, info_len);
            input_len += info_len;
        }
        
        /* Counter byte */
        hmac_input[input_len++] = i;
        
        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        hmac_sha256(t, prk, SHA256_DIGEST_SIZE, hmac_input, input_len);
        
        /* Copy to output */
        to_copy = (okm_len - okm_offset < SHA256_DIGEST_SIZE) ?
                         (okm_len - okm_offset) : SHA256_DIGEST_SIZE;
        memcpy(okm + okm_offset, t, to_copy);
        okm_offset += to_copy;
    }
    
    free(hmac_input);
    secure_zero(t, SHA256_DIGEST_SIZE);
}

/**
 * HKDF-SHA256: Extract-then-Expand Key Derivation
 * RFC 5869
 */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    
    /* Extract */
    hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    
    /* Expand */
    hkdf_expand(okm, okm_len, prk, info, info_len);
    
    /* Zeroize PRK */
    secure_zero(prk, SHA256_DIGEST_SIZE);
    
    return 0;
}

/* ========== AEAD IMPLEMENTATION (AES-CTR + HMAC-SHA256) ========== */

/**
 * AEAD Encrypt: Encrypt-then-MAC using AES-128-CTR + HMAC-SHA256
 * 
 * Construction:
 *   K_enc = SHA256(K || 0x01)[0:16]
 *   K_mac = SHA256(K || 0x02)
 *   C = AES-CTR(K_enc, nonce, plaintext)
 *   tag = HMAC-SHA256(K_mac, AAD || C)[0:16]
 *   output = C || tag
 */
int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[33];
    uint8_t *mac_input;
    uint8_t tag[SHA256_DIGEST_SIZE];
    uint8_t temp_hash[SHA256_DIGEST_SIZE];  /* Temp buffer for SHA256 output */
    
    /* Derive encryption key: K_enc = SHA256(K || 0x01)[0:16] */
    memcpy(kdf_input, key, 32);
    kdf_input[32] = 0x01;
    sha256_hash(temp_hash, kdf_input, 33);
    memcpy(enc_key, temp_hash, 16);  /* Use first 16 bytes */
    
    /* Derive MAC key: K_mac = SHA256(K || 0x02) */
    kdf_input[32] = 0x02;
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Encrypt: C = AES-CTR(K_enc, nonce, plaintext) */
    aes128_ctr_crypt(output, plaintext, pt_len, enc_key, nonce);
    
    /* Compute MAC over AAD || C */
    mac_input = (uint8_t *)malloc(aad_len + pt_len);
    if (!mac_input) {
        secure_zero(enc_key, 16);
        secure_zero(mac_key, 32);
        return -1;
    }
    
    if (aad_len > 0) {
        memcpy(mac_input, aad, aad_len);
    }
    memcpy(mac_input + aad_len, output, pt_len);
    
    hmac_sha256(tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    /* Append truncated tag (16 bytes) */
    memcpy(output + pt_len, tag, AEAD_TAG_LEN);
    *output_len = pt_len + AEAD_TAG_LEN;
    
    /* Cleanup */
    free(mac_input);
    secure_zero(enc_key, 16);
    secure_zero(mac_key, 32);
    secure_zero(tag, SHA256_DIGEST_SIZE);
    
    return 0;
}

/**
 * AEAD Decrypt: Verify-then-Decrypt using AES-128-CTR + HMAC-SHA256
 */
int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[33];
    uint8_t *mac_input;
    uint8_t expected_tag[SHA256_DIGEST_SIZE];
    uint8_t temp_hash[SHA256_DIGEST_SIZE];  /* Temp buffer for SHA256 output */
    size_t pt_len;
    int tag_match;
    
    if (ct_len < AEAD_TAG_LEN) {
        return -1;  /* Invalid ciphertext */
    }
    
    pt_len = ct_len - AEAD_TAG_LEN;
    
    /* Derive keys */
    memcpy(kdf_input, key, 32);
    kdf_input[32] = 0x01;
    sha256_hash(temp_hash, kdf_input, 33);
    memcpy(enc_key, temp_hash, 16);  /* Use first 16 bytes */
    kdf_input[32] = 0x02;
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Verify MAC */
    mac_input = (uint8_t *)malloc(aad_len + pt_len);
    if (!mac_input) {
        secure_zero(enc_key, 16);
        secure_zero(mac_key, 32);
        return -1;
    }
    
    if (aad_len > 0) {
        memcpy(mac_input, aad, aad_len);
    }
    memcpy(mac_input + aad_len, ciphertext, pt_len);
    
    hmac_sha256(expected_tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    /* Constant-time tag comparison */
    tag_match = constant_time_compare(expected_tag, 
                                     ciphertext + pt_len, 
                                     AEAD_TAG_LEN);
    
    free(mac_input);
    secure_zero(mac_key, 32);
    
    if (tag_match != 0) {
        /* Authentication failed */
        secure_zero(enc_key, 16);
        return -1;
    }
    
    /* Decrypt */
    aes128_ctr_crypt(output, ciphertext, pt_len, enc_key, nonce);
    *output_len = pt_len;
    
    secure_zero(enc_key, 16);
    return 0;
}

/* ========== SESSION KEY DERIVATION ========== */

/**
 * Derive master session key from error vector and gateway nonce
 * K_master = HKDF(salt=NULL, IKM=error||N_G, info="master-key")
 */
void derive_master_key(uint8_t *K_master,
                      const uint8_t *error, size_t err_len,
                      const uint8_t *gateway_nonce, size_t nonce_len) {
    uint8_t *ikm;
    const uint8_t info[] = "master-key";
    
    /* Concatenate error vector and gateway nonce */
    ikm = (uint8_t *)malloc(err_len + nonce_len);
    if (!ikm) {
        return;
    }
    
    memcpy(ikm, error, err_len);
    memcpy(ikm + err_len, gateway_nonce, nonce_len);
    
    /* Derive K_master using HKDF */
    hkdf_sha256(NULL, 0, ikm, err_len + nonce_len,
               info, sizeof(info) - 1,
               K_master, MASTER_KEY_LEN);
    
    /* Zeroize IKM */
    secure_zero(ikm, err_len + nonce_len);
    free(ikm);
}

/**
 * Derive ephemeral message key K_i from K_master
 * K_i = HKDF(salt=NULL, IKM=K_master, info="session-key"||SID||counter)
 */
static void derive_message_key(uint8_t *K_i,
                              const uint8_t *K_master,
                              const uint8_t *sid, size_t sid_len,
                              uint32_t counter) {
    uint8_t info[32];  /* "session-key" + SID + counter */
    size_t info_len = 0;
    
    /* info = "session-key" || SID || counter */
    memcpy(info, "session-key", 11);
    info_len = 11;
    
    memcpy(info + info_len, sid, sid_len);
    info_len += sid_len;
    
    /* Append counter in big-endian */
    info[info_len++] = (counter >> 24) & 0xFF;
    info[info_len++] = (counter >> 16) & 0xFF;
    info[info_len++] = (counter >> 8) & 0xFF;
    info[info_len++] = counter & 0xFF;
    
    /* Derive K_i */
    hkdf_sha256(NULL, 0, K_master, MASTER_KEY_LEN,
               info, info_len, K_i, 32);
}

/**
 * Encrypt a message using session key derivation + AEAD
 */
int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[AEAD_NONCE_LEN];
    int ret;
    
    /* Derive ephemeral key K_i */
    derive_message_key(K_i, ctx->K_master, ctx->sid, SID_LEN, ctx->counter);
    
    /* Construct nonce: SID || counter (first 12 bytes) */
    memcpy(nonce, ctx->sid, SID_LEN);
    nonce[8] = (ctx->counter >> 24) & 0xFF;
    nonce[9] = (ctx->counter >> 16) & 0xFF;
    nonce[10] = (ctx->counter >> 8) & 0xFF;
    nonce[11] = ctx->counter & 0xFF;
    
    /* AEAD encrypt with SID as AAD */
    ret = aead_encrypt(out, out_len, plaintext, pt_len,
                      ctx->sid, SID_LEN,
                      K_i, nonce);
    
    /* Zeroize K_i */
    secure_zero(K_i, sizeof(K_i));
    
    return ret;
}

/**
 * Decrypt a message using session key derivation + AEAD
 * Includes replay protection via counter check
 */
int session_decrypt(session_entry_t *se, uint32_t counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[AEAD_NONCE_LEN];
    int ret;
    
    /* Replay protection: reject counter <= last_seq */
    if (counter <= se->last_seq) {
        return -1;  /* Replay attack detected */
    }
    
    /* Derive ephemeral key K_i */
    derive_message_key(K_i, se->K_master, se->sid, SID_LEN, counter);
    
    /* Construct nonce */
    memcpy(nonce, se->sid, SID_LEN);
    nonce[8] = (counter >> 24) & 0xFF;
    nonce[9] = (counter >> 16) & 0xFF;
    nonce[10] = (counter >> 8) & 0xFF;
    nonce[11] = counter & 0xFF;
    
    /* AEAD decrypt with SID as AAD */
    ret = aead_decrypt(out, out_len, ct, ct_len,
                      se->sid, SID_LEN,
                      K_i, nonce);
    
    if (ret == 0) {
        /* Update last_seq only on successful decryption */
        se->last_seq = counter;
    }
    
    /* Zeroize K_i */
    secure_zero(K_i, sizeof(K_i));
    
    return ret;
}

/**
 * Key ratcheting (future work - placeholder)
 */
void ratchet_master(session_ctx_t *ctx, const uint8_t *nonce, size_t nonce_len) {
    uint8_t new_K[MASTER_KEY_LEN];
    const uint8_t info[] = "ratchet";
    
    hkdf_sha256(nonce, nonce_len, ctx->K_master, MASTER_KEY_LEN,
               info, sizeof(info) - 1, new_K, MASTER_KEY_LEN);
    
    memcpy(ctx->K_master, new_K, MASTER_KEY_LEN);
    secure_zero(new_K, sizeof(new_K));
}
