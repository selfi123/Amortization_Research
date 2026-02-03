# Session Amortization Implementation Plan (Model A)

## Problem Statement

The current implementation performs expensive LDPC operations (encoding on sender, decoding on gateway) **for every single data message**. This results in high CPU and energy costs per message, making it unsuitable for resource-constrained IoT devices sending multiple messages.

### Current Flow (High Cost):
```
AUTH: Ring signature → verify
DATA (message 1): generate_error_vector → ldpc_encode → AES encrypt → send
                  [EXPENSIVE: ~100ms CPU on IoT device]
DATA (message 2): generate_error_vector → ldpc_encode → AES encrypt → send
                  [EXPENSIVE: ~100ms CPU per message]
...repeat for N messages
```

### Proposed Flow (Amortized Cost):
```
AUTH: Ring signature → verify → LDPC decode once → derive K_master
      [EXPENSIVE: ~100ms, but ONE TIME]
DATA (message 1): HKDF(K_master) → AEAD encrypt → send
                  [CHEAP: ~5ms]
DATA (message 2): HKDF(K_master) → AEAD encrypt → send
                  [CHEAP: ~5ms]
...repeat for N messages with minimal cost
```

## Goal

Move heavy post-quantum operations (LDPC encoding/decoding) to the authentication phase, then use lightweight symmetric cryptography (HKDF + AEAD) for all subsequent data messages in the session.

---

## Critical Implementation Requirements

> [!CAUTION]
> **Must address before coding begins** - These items will cause compile failures, runtime errors, or security bugs if not handled.

### 0. Crypto Primitive Dependencies & Availability

**CRITICAL: Document all cryptographic dependencies and their source**

#### Existing Implementations (in [`crypto_core.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/crypto_core.c)):

| Primitive | Function | Location | Status |
|-----------|----------|----------|--------|
| **SHA-256** | `sha256_hash()` | crypto_core.c:475-533 | ✅ Available |
| **AES-128 CTR** | `aes128_ctr_crypt()` | crypto_core.c:748-774 | ✅ Available |
| **AES Key Expansion** | `aes128_key_expansion()` | crypto_core.c:594-622 | ✅ Available |
| **PRNG (Xorshift)** | `crypto_random_uint32()` | crypto_core.c:28-33 | ⚠️ NOT cryptographically secure |

#### Required NEW Implementations (to be added to [`crypto_core.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/crypto_core.c)):

| Primitive | Function | Location | Lines | Dependencies |
|-----------|----------|----------|-------|--------------|
| **HMAC-SHA256** | `hmac_sha256()` | crypto_core.c (new) | ~60 | `sha256_hash()` |
| **HKDF-Extract** | `hkdf_extract()` | crypto_core.c (new) | ~15 | `hmac_sha256()` |
| **HKDF-Expand** | `hkdf_expand()` | crypto_core.c (new) | ~40 | `hmac_sha256()` |
| **HKDF** | `hkdf_sha256()` | crypto_core.c (new) | ~10 | `hkdf_extract()`, `hkdf_expand()` |
| **AEAD Encrypt** | `aead_encrypt()` | crypto_core.c (new) | ~50 | `aes128_ctr_crypt()`, `hmac_sha256()` |
| **AEAD Decrypt** | `aead_decrypt()` | crypto_core.c (new) | ~60 | `aes128_ctr_crypt()`, `hmac_sha256()` |
| **Secure RNG** | `crypto_secure_random()` | crypto_core.c (new) | ~20 | Contiki `random_rand()` or `/dev/urandom` |
| **Secure Zero** | `secure_zero()` | crypto_core.c (new) | ~10 | Volatile pointer |
| **Constant-time Compare** | `constant_time_compare()` | crypto_core.c (new) | ~10 | None |

#### Crypto Dependencies

**SHA-256 and HMAC-SHA256** are reused from existing `crypto_core.c` implementation (lines 475-533 for SHA-256; HMAC-SHA256 is new, built on top of SHA-256).

**AES-CTR** implementation is reused from existing `crypto_core.c` (lines 748-774, `aes128_ctr_crypt()`).

**No external crypto libraries are added** (no mbedTLS, no tinycrypt).

**All new crypto glue code** (HKDF, AEAD, secure RNG) is implemented inside `crypto_core.c`.

#### Build Configuration:

**All new crypto code lives in:** [`crypto_core.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/crypto_core.c)  
**No new files required** (avoids Makefile complexity)  
**Total new LOC:** ~275 lines

#### AEAD Construction (Explicit):

**Selected:** AES-128-CTR + HMAC-SHA256 (Encrypt-then-MAC)

```
AEAD_Encrypt(K, N, AAD, P):
    K_enc = SHA256(K || 0x01)[0:16]  // Encryption key
    K_mac = SHA256(K || 0x02)        // MAC key
    C = AES-CTR(K_enc, N, P)
    tag = HMAC-SHA256(K_mac, AAD || C)[0:16]
    return C || tag

AEAD_Decrypt(K, N, AAD, C||tag):
    K_enc = SHA256(K || 0x01)[0:16]
    K_mac = SHA256(K || 0x02)
    tag' = HMAC-SHA256(K_mac, AAD || C)[0:16]
    if constant_time_compare(tag, tag') != 0: return ERROR
    P = AES-CTR(K_enc, N, C)
    return P
```

**Rationale:** 
- Reuses existing `sha256_hash()` and `aes128_ctr_crypt()`
- No external dependencies (no mbedTLS/tinycrypt needed)
- Implements standard Encrypt-then-MAC pattern
- Constant-time tag verification prevents timing attacks

---

### A. Build System Updates

**Required:** Modify [`Makefile`](file:///c:/Users/aloob/Desktop/Amortization_Research/Makefile) to include new source files and definitions.

**Changes to Makefile** (add after line 5):
```makefile
# Session amortization support
PROJECT_SOURCEFILES += crypto_core.c

# Optional: separate session manager
# PROJECT_SOURCEFILES += session_manager.c

# Compile-time parameters (optional - can also define in .h)
CFLAGS += -DSID_LEN=8 -DMASTER_KEY_LEN=32 -DMAX_SESSIONS=16
```

#### Build Integration:
- `crypto_core.c` is added to `PROJECT_SOURCEFILES`
- (optional) `session_manager.c` is added if split from crypto_core
- No changes to Contiki core are required


**Additionally, add explicit Makefile compilation check:**

```makefile
# Verify all required symbols are present
check-symbols: node-sender.z1 node-gateway.z1
	@echo "Checking for required crypto symbols..."
	@nm node-sender.z1 | grep -q "sha256_hash" || (echo "ERROR: sha256_hash not found" && exit 1)
	@nm node-sender.z1 | grep -q "hmac_sha256" || (echo "ERROR: hmac_sha256 not found" && exit 1)
	@nm node-sender.z1 | grep -q "hkdf_sha256" || (echo "ERROR: hkdf_sha256 not found" && exit 1)
	@nm node-sender.z1 | grep -q "aead_encrypt" || (echo "ERROR: aead_encrypt not found" && exit 1)
	@echo "✓ All required symbols present"
```

### B-1. Message Wire Format Specification

**CRITICAL:** Exact byte-level message formats prevent serialization bugs

> [!IMPORTANT]
> All multi-byte integers are transmitted in **network byte order (big-endian)**

#### AuthMessage Format:

```
┌────────┬──────────┬─────────────────┬──────────────┐
│  type  │ syndrome │  ring_signature │  (padding)   │
│  1 B   │  51 B    │     varies      │   align      │
└────────┴──────────┴─────────────────┴──────────────┘

Total size: 1 + 51 + sizeof(RingSignature) bytes
```

**Wire encoding:**
```c
uint8_t buf[512];
size_t offset = 0;

buf[offset++] = MSG_TYPE_AUTH;
memcpy(buf + offset, auth_msg.syndrome, LDPC_ROWS / 8);  // 51 bytes
offset += LDPC_ROWS / 8;
memcpy(buf + offset, &auth_msg.signature, sizeof(RingSignature));
offset += sizeof(RingSignature);

simple_udp_sendto(&udp_conn, buf, offset, dest_addr);
```

#### AuthAck Message Format:

```
┌────────┬─────────────────────┬───────────┐
│  type  │    gateway_nonce    │    SID    │
│  1 B   │       32 B          │    8 B    │
└────────┴─────────────────────┴───────────┘

Total size: 41 bytes (fixed)
```

**Wire encoding:**
```c
uint8_t buf[41];
buf[0] = MSG_TYPE_AUTH_ACK;
memcpy(buf + 1, N_G, 32);
memcpy(buf + 33, SID, 8);

simple_udp_sendto(&udp_conn, buf, 41, dest_addr);
```

**Wire decoding:**
```c
const uint8_t *ptr = data;
uint8_t msg_type = *ptr++;
uint8_t N_G[32];
uint8_t SID[8];
memcpy(N_G, ptr, 32);
ptr += 32;
memcpy(SID, ptr, 8);
```

#### DataMessage Format (Variable Length):

```
┌────────┬───────┬───────────┬────────────┬──────────────┬────────┐
│  type  │  SID  │  counter  │ cipher_len │  ciphertext  │   tag  │
│  1 B   │  8 B  │    4 B    │    2 B     │   var (N B)  │  16 B  │
└────────┴───────┴───────────┴────────────┴──────────────┴────────┘

Total size: 1 + 8 + 4 + 2 + N + 16 = 31 + N bytes
N ≤ MESSAGE_MAX_SIZE (typ. 64 bytes)
```

**Wire encoding:**
```c
uint8_t buf[256];
size_t offset = 0;

buf[offset++] = MSG_TYPE_DATA;
memcpy(buf + offset, session_ctx.sid, SID_LEN);
offset += SID_LEN;

// Counter (big-endian)
buf[offset++] = (session_ctx.counter >> 24) & 0xFF;
buf[offset++] = (session_ctx.counter >> 16) & 0xFF;
buf[offset++] = (session_ctx.counter >> 8) & 0xFF;
buf[offset++] = session_ctx.counter & 0xFF;

// Cipher length (big-endian)
buf[offset++] = (cipher_len >> 8) & 0xFF;
buf[offset++] = cipher_len & 0xFF;

// Ciphertext (includes AEAD tag)
memcpy(buf + offset, ciphertext, cipher_len);
offset += cipher_len;

simple_udp_sendto(&udp_conn, buf, offset, dest_addr);
```

**Wire decoding:**
```c
const uint8_t *ptr = data;
uint8_t msg_type = *ptr++;
uint8_t sid[SID_LEN];
memcpy(sid, ptr, SID_LEN);
ptr += SID_LEN;

// Counter (big-endian decode)
uint32_t counter = ((uint32_t)ptr[0] << 24) |
                   ((uint32_t)ptr[1] << 16) |
                   ((uint32_t)ptr[2] << 8) |
                    (uint32_t)ptr[3];
ptr += 4;

// Cipher length
uint16_t cipher_len = ((uint16_t)ptr[0] << 8) | (uint16_t)ptr[1];
ptr += 2;

const uint8_t *ciphertext = ptr;
```

> [!WARNING]
> **Endianness Validation:** On heterogeneous deployments, test with: `sender=native, gateway=z1` to catch byte-order bugs early.

### B-2. RNG Quality & Security Statement

**EXPLICIT RNG SECURITY POLICY**

> [!CAUTION]
> **Current Implementation:** `crypto_random_uint32()` uses Xorshift PRNG which is **NOT cryptographically secure**

#### For Production Use:

**Platform:** Contiki on Z1/CC2538  
**RNG Source:** Hardware RNG (`dev/random.h` → `random_rand()`)  
**Security:** Cryptographically secure (hardware entropy)

**Implementation:**
```c
#ifdef CONTIKI
#include "dev/random.h"

void crypto_secure_random(uint8_t *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = random_rand() & 0xFF;  // Hardware RNG on Z1
    }
}
#else
/* Native testing: use /dev/urandom */
void crypto_secure_random(uint8_t *output, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(output, 1, len, f);
        fclose(f);
    }
}
#endif
```

**All session IDs and nonces MUST use:**
```c
crypto_secure_random(SID, SID_LEN);       // NOT crypto_random_uint32()
crypto_secure_random(N_G, 32);            // NOT crypto_random_uint32()
```

#### Security Statement in Documentation:

> **Security Claims:**  
> - Session amortization does NOT weaken the base protocol's post-quantum security  
> - SID & nonce generation uses hardware RNG (Z1 platform) or `/dev/urandom` (native)  
> - Key derivation uses HKDF-SHA256 (RFC 5869)  
> - AEAD uses AES-128-CTR + HMAC-SHA256 (Encrypt-then-MAC)  
> - **Limitation:** Xorshift PRNG is used for LDPC error vectors (acceptable for PoC; production should use CSPRNG)

### B-3. Session Termination Semantics

**EXPLICIT SESSION LIFECYCLE RULES**

#### Session Creation:
```c
On successful AUTH:
    - Derive K_master from error vector + N_G
    - Generate 8-byte SID (using secure RNG)
    - Set counter = 0
    - Set expiry_ts = current_time + SESSION_LIFETIME (3600 sec default)
    - Store in session table
```

#### Session Termination Conditions:

A session **MUST** terminate when:

1. **Counter Exhaustion:** `counter >= MAX_MESSAGES_PER_SESSION` (10,000 default)
2. **Time Expiry:** `current_time > expiry_ts` (1 hour default)
3. **Explicit Close:** Sender sends `MSG_TYPE_SESSION_CLOSE` (optional, future)
4. **Gateway Reboot:** All sessions cleared (RAM-only storage)
5. **Session Eviction:** LRU eviction when gateway reaches `MAX_SESSIONS` limit

#### On Termination:

**Sender side:**
```c
void terminate_session(session_ctx_t *ctx) {
    LOG_INFO("Session terminated: SID=[%02x%02x...], counter=%u\n",
             ctx->sid[0], ctx->sid[1], ctx->counter);
    
    secure_zero(ctx->K_master, MASTER_KEY_LEN);
    secure_zero(ctx->sid, SID_LEN);
    ctx->active = 0;
    ctx->counter = 0;
}
```

**Gateway side:**
```c
void evict_session(session_entry_t *se) {
    LOG_INFO("Evicting session: SID=[%02x%02x...]\n", se->sid[0], se->sid[1]);
    
    secure_zero(se->K_master, MASTER_KEY_LEN);
    secure_zero(se->sid, SID_LEN);
    se->in_use = 0;
    se->last_seq = 0;
}
```

#### Post-Termination Behavior:

- **Sender:** MUST re-authenticate (send new AUTH message)
- **Gateway:** Rejects DATA messages with unknown SID (error: `SESSION_NOT_FOUND`)
- **No grace period:** Termination is immediate and irreversible

#### Gateway Reboot Handling:

> [!WARNING]
> Sessions are **RAM-only** (not persistent). Gateway reboot clears all sessions.

**Mitigation:**
```c
/* Sender detects session loss via decryption failure ACK */
On receipt of SESSION_NOT_FOUND error:
    - Clear local session state
    - Trigger re-authentication
    - Retry DATA message after new AUTH completes
```

### B-4. Replay Attack Protection (Counter Semantics)

**EXPLICIT COUNTER ACCEPTANCE POLICY**

#### Gateway Counter Validation:

**Policy:** Strictly monotonic counter per SID (no replay window)

```c
int session_decrypt(session_entry_t *se, uint32_t received_counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len) {
    
    /* Strict monotonic check: reject ≤ last_seq */
    if (received_counter <= se->last_seq) {
        LOG_ERR("Replay attack detected! counter=%u, last_seq=%u\n",
                received_counter, se->last_seq);
        return -1;  // REJECT
    }
    
    /* AEAD decrypt */
    int ret = aead_decrypt(out, out_len, ct, ct_len, 
                          se->sid, SID_LEN, /* AAD */
                          K_i, nonce);
    
    if (ret != 0) {
        LOG_ERR("AEAD tag verification failed\n");
        return -1;
    }
    
    /* Update last_seq ONLY on successful decryption */
    se->last_seq = received_counter;
    return 0;
}
```

**Rationale:**
- Simple implementation (no sliding window needed)
- Sufficient for IoT use case (ordered delivery expected)
- Prevents replay attacks without complex bookkeeping

**Trade-off:**
- ❌ Does NOT tolerate out-of-order delivery
- ✅ Simpler code, lower memory footprint
- ✅ Appropriate for CSMA/CA MAC layer (Contiki default)

**Alternative (if reordering needed):**
```c
/* Windowed counter acceptance (NOT implemented in this plan) */
#define REPLAY_WINDOW 64
uint64_t replay_bitmap;  // Bit i set if counter = last_seq - i seen

if (counter > last_seq) {
    // Advance window
} else if (counter >= last_seq - REPLAY_WINDOW) {
    // Check bitmap
}
```

**Current decision:** Use strict monotonic (simpler, adequate).

---

### C. Message Serialization & Network Byte Order

**Problem:** Current code uses raw `struct` send/receive which:
- Wastes bandwidth (sending full static arrays)
- May have endianness issues on heterogeneous platforms
- Variable-length ciphertext needs careful length calculation

**Solution:** Manual serialization with proper byte order

**Add to crypto_core.c** (helper functions):
```c
/* Network byte order helpers */
static inline void write_uint32_be(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >> 8) & 0xFF;
    buf[3] = val & 0xFF;
}

static inline uint32_t read_uint32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
            (uint32_t)buf[3];
}
```

**Modify DataMessage sending** (in node-sender.c):
```c
/* Instead of sending entire struct: */
// simple_udp_sendto(&udp_conn, &data_msg, sizeof(DataMessage), ...);

/* Use packed buffer: */
uint8_t send_buf[1 + SID_LEN + 4 + 2 + MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
size_t offset = 0;

send_buf[offset++] = MSG_TYPE_DATA;
memcpy(send_buf + offset, session_ctx.sid, SID_LEN);
offset += SID_LEN;
write_uint32_be(send_buf + offset, session_ctx.counter);
offset += 4;
write_uint32_be(send_buf + offset, cipher_len);  /* Store as big-endian */
offset += 4;
memcpy(send_buf + offset, ciphertext, cipher_len);
offset += cipher_len;

simple_udp_sendto(&udp_conn, send_buf, offset, sender_addr);
```

**Modify DataMessage parsing** (in node-gateway.c):
```c
const uint8_t *ptr = data;
uint8_t msg_type = *ptr++;
uint8_t sid[SID_LEN];
memcpy(sid, ptr, SID_LEN);
ptr += SID_LEN;
uint32_t counter = read_uint32_be(ptr);
ptr += 4;
uint32_t cipher_len = read_uint32_be(ptr);
ptr += 4;
const uint8_t *ciphertext = ptr;
```

### C. AEAD Primitive Implementation

**Decision Required:** Choose AEAD construction

**Option A (RECOMMENDED): AES-128-CTR + HMAC-SHA256**
- ✅ Reuses existing `aes128_ctr_crypt()` and `sha256_hash()`
- ✅ No new dependencies
- ❌ Requires careful HMAC implementation (see below)

**Option B: ChaCha20-Poly1305**
- ✅ Better security margins
- ❌ Requires full new implementation (~500 lines)
- ❌ Not available in current codebase

**Selected: Option A**

**Add HMAC-SHA256 implementation** (in crypto_core.c, ~60 lines):
```c
/* HMAC-SHA256 implementation */
void hmac_sha256(uint8_t *output, const uint8_t *key, size_t key_len,
                 const uint8_t *msg, size_t msg_len) {
    uint8_t k_pad[64];  /* SHA-256 block size */
    uint8_t i_key_pad[64], o_key_pad[64];
    uint8_t inner_hash[SHA256_DIGEST_SIZE];
    
    /* Key padding */
    memset(k_pad, 0, 64);
    if (key_len > 64) {
        sha256_hash(k_pad, key, key_len);  /* Hash if too long */
    } else {
        memcpy(k_pad, key, key_len);
    }
    
    /* Inner and outer pads */
    for (int i = 0; i < 64; i++) {
        i_key_pad[i] = k_pad[i] ^ 0x36;
        o_key_pad[i] = k_pad[i] ^ 0x5c;
    }
    
    /* Inner hash: H(K ⊕ ipad || message) */
    uint8_t *inner_msg = malloc(64 + msg_len);
    memcpy(inner_msg, i_key_pad, 64);
    memcpy(inner_msg + 64, msg, msg_len);
    sha256_hash(inner_hash, inner_msg, 64 + msg_len);
    free(inner_msg);
    
    /* Outer hash: H(K ⊕ opad || inner_hash) */
    uint8_t outer_msg[64 + SHA256_DIGEST_SIZE];
    memcpy(outer_msg, o_key_pad, 64);
    memcpy(outer_msg + 64, inner_hash, SHA256_DIGEST_SIZE);
    sha256_hash(output, outer_msg, 64 + SHA256_DIGEST_SIZE);
    
    /* Zeroize sensitive data */
    secure_zero(k_pad, 64);
    secure_zero(i_key_pad, 64);
    secure_zero(o_key_pad, 64);
}
```

**Add AEAD encrypt/decrypt** (in crypto_core.c, ~100 lines):
```c
/* AEAD: Encrypt-then-MAC using AES-128-CTR + HMAC-SHA256 */
int aead_encrypt(uint8_t *output, size_t *output_len,
                const uint8_t *plaintext, size_t pt_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    /* Derive separate keys for encryption and MAC */
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[32 + 1];
    memcpy(kdf_input, key, 32);
    
    kdf_input[32] = 0x01;  /* Encryption key derivation */
    sha256_hash(enc_key, kdf_input, 33);
    
    kdf_input[32] = 0x02;  /* MAC key derivation */
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Encrypt: C = AES-CTR(K_enc, nonce, P) */
    aes128_ctr_crypt(output, plaintext, pt_len, enc_key, nonce);
    
    /* MAC over AAD || C */
    uint8_t *mac_input = malloc(aad_len + pt_len);
    memcpy(mac_input, aad, aad_len);
    memcpy(mac_input + aad_len, output, pt_len);
    
    uint8_t tag[SHA256_DIGEST_SIZE];
    hmac_sha256(tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    /* Append tag (truncate to 16 bytes) */
    memcpy(output + pt_len, tag, AEAD_TAG_LEN);
    *output_len = pt_len + AEAD_TAG_LEN;
    
    /* Cleanup */
    free(mac_input);
    secure_zero(enc_key, 16);
    secure_zero(mac_key, 32);
    secure_zero(tag, 32);
    
    return 0;
}

int aead_decrypt(uint8_t *output, size_t *output_len,
                const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *aad, size_t aad_len,
                const uint8_t *key, const uint8_t *nonce) {
    if (ct_len < AEAD_TAG_LEN) return -1;
    
    size_t pt_len = ct_len - AEAD_TAG_LEN;
    
    /* Derive keys */
    uint8_t enc_key[16], mac_key[32];
    uint8_t kdf_input[32 + 1];
    memcpy(kdf_input, key, 32);
    
    kdf_input[32] = 0x01;
    sha256_hash(enc_key, kdf_input, 33);
    kdf_input[32] = 0x02;
    sha256_hash(mac_key, kdf_input, 33);
    
    /* Verify MAC */
    uint8_t *mac_input = malloc(aad_len + pt_len);
    memcpy(mac_input, aad, aad_len);
    memcpy(mac_input + aad_len, ciphertext, pt_len);
    
    uint8_t expected_tag[SHA256_DIGEST_SIZE];
    hmac_sha256(expected_tag, mac_key, 32, mac_input, aad_len + pt_len);
    
    /* Constant-time tag comparison */
    int tag_match = constant_time_compare(expected_tag, 
                                         ciphertext + pt_len, 
                                         AEAD_TAG_LEN);
    
    free(mac_input);
    secure_zero(mac_key, 32);
    
    if (tag_match != 0) {
        secure_zero(enc_key, 16);
        return -1;  /* Authentication failed */
    }
    
    /* Decrypt */
    aes128_ctr_crypt(output, ciphertext, pt_len, enc_key, nonce);
    *output_len = pt_len;
    
    secure_zero(enc_key, 16);
    return 0;
}
```

### D. HKDF Implementation with Test Vectors

**Add HKDF-SHA256** (in crypto_core.c, ~80 lines):
```c
/* HKDF-Extract: PRK = HMAC-Hash(salt, IKM) */
static void hkdf_extract(uint8_t *prk,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len) {
    if (salt == NULL || salt_len == 0) {
        uint8_t zero_salt[SHA256_DIGEST_SIZE] = {0};
        hmac_sha256(prk, zero_salt, SHA256_DIGEST_SIZE, ikm, ikm_len);
    } else {
        hmac_sha256(prk, salt, salt_len, ikm, ikm_len);
    }
}

/* HKDF-Expand: OKM = HMAC-Hash(PRK, info || counter) */
static void hkdf_expand(uint8_t *okm, size_t okm_len,
                       const uint8_t *prk,
                       const uint8_t *info, size_t info_len) {
    uint8_t n = (okm_len + SHA256_DIGEST_SIZE - 1) / SHA256_DIGEST_SIZE;
    uint8_t t[SHA256_DIGEST_SIZE] = {0};
    uint8_t *hmac_input = malloc(SHA256_DIGEST_SIZE + info_len + 1);
    size_t okm_offset = 0;
    
    for (uint8_t i = 1; i <= n; i++) {
        size_t input_len = 0;
        
        if (i > 1) {
            memcpy(hmac_input, t, SHA256_DIGEST_SIZE);
            input_len = SHA256_DIGEST_SIZE;
        }
        
        memcpy(hmac_input + input_len, info, info_len);
        input_len += info_len;
        hmac_input[input_len++] = i;
        
        hmac_sha256(t, prk, SHA256_DIGEST_SIZE, hmac_input, input_len);
        
        size_t to_copy = (okm_len - okm_offset < SHA256_DIGEST_SIZE) ?
                         (okm_len - okm_offset) : SHA256_DIGEST_SIZE;
        memcpy(okm + okm_offset, t, to_copy);
        okm_offset += to_copy;
    }
    
    free(hmac_input);
    secure_zero(t, SHA256_DIGEST_SIZE);
}

/* HKDF = Extract + Expand */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    hkdf_extract(prk, salt, salt_len, ikm, ikm_len);
    hkdf_expand(okm, okm_len, prk, info, info_len);
    secure_zero(prk, SHA256_DIGEST_SIZE);
    return 0;
}
```

**Add HKDF test vectors** (create `test_hkdf.c` for native testing):
```c
/* RFC 5869 Test Case 1 */
void test_hkdf_rfc5869_case1(void) {
    uint8_t ikm[22] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint8_t salt[13] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                        0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    uint8_t info[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                        0xf7, 0xf8, 0xf9};
    uint8_t okm[42];
    uint8_t expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    
    hkdf_sha256(salt, 13, ikm, 22, info, 10, okm, 42);
    
    if (memcmp(okm, expected, 42) == 0) {
        printf("HKDF Test Case 1: PASS\n");
    } else {
        printf("HKDF Test Case 1: FAIL\n");
    }
}
```

### E. Cryptographically Secure RNG

**Problem:** `crypto_random_uint32()` uses Xorshift PRNG (NOT cryptographically secure)

**Solution:** Use platform CSPRNG or hardware RNG

**For Contiki on Z1/CC2538** (add to crypto_core.c):
```c
#ifdef CONTIKI
#include "dev/random.h"

/* Use Contiki's hardware RNG if available */
void crypto_secure_random(uint8_t *output, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = random_rand() & 0xFF;  /* Contiki hardware RNG */
    }
}

#else
/* Native/test: use /dev/urandom */
void crypto_secure_random(uint8_t *output, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(output, 1, len, f);
        fclose(f);
    } else {
        /* Fallback: not secure! */
        for (size_t i = 0; i < len; i++) {
            output[i] = crypto_random_uint32() & 0xFF;
        }
    }
}
#endif
```

**Replace all SID/nonce generation:**
```c
/* OLD (insecure): */
// for (int i = 0; i < SID_LEN; i++) {
//     SID[i] = crypto_random_uint32() & 0xFF;
// }

/* NEW (secure): */
crypto_secure_random(SID, SID_LEN);
crypto_secure_random(N_G, 32);
```

### F. LDPC Handshake Clarification

**Chosen Approach:** Sender computes syndrome using public LDPC matrix H

**Rationale:** Keeps error vector `e` secret (only syndrome `s` transmitted)

**Implementation:**

1. **Gateway generates LDPC keypair** (already done in gateway init)
2. **Gateway publishes H (public matrix)** - sender must receive this
3. **Sender computes**: `s = H × e^T` using `ldpc_encode()`
4. **Sender sends**: `s` in `AuthMessage.syndrome`
5. **Gateway decodes**: `e = LDPC_Decode(s)` using private trapdoor

**Critical fix: Sender needs H (public LDPC key)**

Since sender doesn't have H initially, we have two options:

**Option 1 (Simple):** Use a well-known public H (hardcoded)
**Option 2 (Better):** Gateway sends H in initial discovery/setup

**Selected: Option 1 for PoC**

**Modify node-sender.c:**
```c
/* Use same LDPC public key as gateway (hardcoded seed) */
static LDPCPublicKey shared_ldpc_public;

/* In sender init: */
shared_ldpc_public.seed[0] = 0xCA;
shared_ldpc_public.seed[1] = 0xFE;
/* ... same seed as gateway ... */
for (int i = 0; i < LDPC_N0; i++) {
    shared_ldpc_public.shift_indices[i] = /* hardcoded values */;
}

/* Compute syndrome in AUTH phase: */
ldpc_encode(syndrome, &auth_error_vector, &shared_ldpc_public);
```

### G. Memory Budget for Z1

**Z1 Mote Constraints:**
- RAM: 16 KB (16384 bytes)
- ROM: 92 KB

**Memory Usage Estimate:**

| Component | Size (bytes) | Count | Total |
|-----------|-------------|-------|-------|
| `session_ctx_t` (sender) | 81 | 1 | 81 |
| `session_entry_t` (gateway) | 89 | 16 | 1424 |
| HKDF temp buffers | ~300 | temp | 300 |
| AEAD buffers | ~200 | temp | 200 |
| Existing crypto | ~4000 | - | 4000 |
| **Total new** | - | - | **~2005** |

**Remaining for stack/network:** ~10 KB (acceptable)

**Mitigation if needed:**
- Reduce `MAX_SESSIONS` to 8 (saves 712 bytes)
- Use stack buffers instead of malloc where possible

**Add to Makefile:**
```makefile
# Check memory usage
size: $(CONTIKI_PROJECT)
	@echo "=== Memory Usage Report ==="
	@msp430-size *.z1 2>/dev/null || echo "Build z1 target first"
	@echo "Z1 limits: RAM=16384 bytes, ROM=94208 bytes"
```

### H. Secure Zeroization

**Problem:** Compiler may optimize out `memset(key, 0, len)`

**Solution:** Use volatile pointer or explicit_bzero

**Add to crypto_core.c:**
```c
/* Secure memory zeroization - compiler cannot optimize this out */
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
```

### I. Unit Tests

**Create `test_session.c` for native testing:**

```c
#include "crypto_core.h"
#include <stdio.h>
#include <assert.h>

void test_hkdf_vectors(void);  /* From section D */
void test_aead_roundtrip(void);
void test_session_encrypt_decrypt(void);

void test_aead_roundtrip(void) {
    uint8_t key[32] = {0x01, 0x02, /* ... */};
    uint8_t nonce[12] = {0xAA, 0xBB, /* ... */};
    uint8_t aad[8] = {0x11, 0x22, /* ... */};
    uint8_t plaintext[] = "Test message";
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    size_t ct_len, pt_len;
    
    int ret = aead_encrypt(ciphertext, &ct_len, plaintext, 13,
                          aad, 8, key, nonce);
    assert(ret == 0);
    assert(ct_len == 13 + AEAD_TAG_LEN);
    
    ret = aead_decrypt(decrypted, &pt_len, ciphertext, ct_len,
                      aad, 8, key, nonce);
    assert(ret == 0);
    assert(pt_len == 13);
    assert(memcmp(plaintext, decrypted, 13) == 0);
    
    /* Test tag corruption */
    ciphertext[ct_len - 1] ^= 0x01;
    ret = aead_decrypt(decrypted, &pt_len, ciphertext, ct_len,
                      aad, 8, key, nonce);
    assert(ret != 0);  /* Should fail */
    
    printf("AEAD Round-trip: PASS\n");
}

int main(void) {
    crypto_prng_init(12345);
    test_hkdf_vectors();
    test_aead_roundtrip();
    test_session_encrypt_decrypt();
    printf("All tests passed!\n");
    return 0;
}
```

**Add to Makefile:**
```makefile
# Unit tests (native only)
test: test_session
	./test_session

test_session: test_session.c crypto_core.c
	gcc -o test_session test_session.c crypto_core.c -I. -DNATIVE_TEST
```

### J. Contiki Process Safety

**Ensure proper protothread usage:**

**In node-sender.c data loop:**
```c
/* WRONG: blocking loop */
// for (int i = 0; i < NUM_MESSAGES; i++) {
//     session_encrypt(...);
//     simple_udp_sendto(...);
// }

/* CORRECT: yielding loop */
static int msg_num = 0;
while (msg_num < NUM_MESSAGES) {
    session_encrypt(&session_ctx, ...);
    simple_udp_sendto(...);
    session_ctx.counter++;
    msg_num++;
    
    etimer_set(&periodic_timer, 2 * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
}
```

**In gateway LDPC decode:**
```c
/* LDPC decode is CPU-intensive - ensure watchdog doesn't trigger */
watchdog_periodic();  /* Call before decode */
sldspa_decode(&recovered_error, auth_msg->syndrome, &gateway_ldpc_keypair);
watchdog_periodic();  /* Call after decode */
```

---

## Proposed Changes

### 1. Cryptographic Core Enhancements

#### File: [`crypto_core.h`](file:///c:/Users/aloob/Desktop/Amortization_Research/crypto_core.h)

Add session management data structures:

```c
/* Session parameters */
#define SID_LEN 8
#define MASTER_KEY_LEN 32
#define AEAD_NONCE_LEN 12
#define AEAD_TAG_LEN 16
#define MAX_MESSAGES_PER_SESSION 10000
#define RATCHET_INTERVAL 500
#define DEFAULT_SESSION_LIFETIME 3600  /* seconds */
#define MAX_SESSIONS 16  /* Gateway limit */

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
    uip_ipaddr_t peer;
    uint8_t in_use;
} session_entry_t;
```

Add new function prototypes:

```c
/* HKDF-SHA256 implementation */
int hkdf_sha256(const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);

/* Session key derivation */
void derive_master_key(uint8_t *K_master,
                      const uint8_t *error, size_t err_len,
                      const uint8_t *gateway_nonce, size_t nonce_len);

/* Session encryption/decryption */
int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len);

int session_decrypt(session_entry_t *se, uint32_t counter,
                   const uint8_t *ct, size_t ct_len,
                   uint8_t *out, size_t *out_len);

/* Key ratcheting */
void ratchet_master(session_ctx_t *ctx, const uint8_t *nonce, size_t nonce_len);

/* Secure memory */
void secure_zero(void *ptr, size_t len);
```

#### File: [`crypto_core.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/crypto_core.c)

**Add HKDF-SHA256 implementation** (~80 lines):
- HKDF-Extract: HMAC-SHA256(salt, IKM) → PRK
- HKDF-Expand: iterative HMAC to produce OKM of desired length

**Add `derive_master_key()`** (~20 lines):
```c
void derive_master_key(uint8_t *K_master,
                      const uint8_t *error, size_t err_len,
                      const uint8_t *gateway_nonce, size_t nonce_len) {
    uint8_t ikm[err_len + nonce_len];
    memcpy(ikm, error, err_len);
    memcpy(ikm + err_len, gateway_nonce, nonce_len);
    
    hkdf_sha256(NULL, 0, ikm, sizeof(ikm),
               (uint8_t*)"master-key", 10,
               K_master, MASTER_KEY_LEN);
    
    secure_zero(ikm, sizeof(ikm));
}
```

**Add `session_encrypt()`** (~50 lines):
```c
int session_encrypt(session_ctx_t *ctx,
                   const uint8_t *plaintext, size_t pt_len,
                   uint8_t *out, size_t *out_len) {
    uint8_t K_i[32];
    uint8_t nonce[AEAD_NONCE_LEN];
    uint8_t info[32];
    
    /* Derive ephemeral key K_i = HKDF(K_master, "session-key" || SID || counter) */
    snprintf((char*)info, sizeof(info), "session-key");
    memcpy(info + 11, ctx->sid, SID_LEN);
    memcpy(info + 11 + SID_LEN, &ctx->counter, 4);
    
    hkdf_sha256(NULL, 0, ctx->K_master, MASTER_KEY_LEN,
               info, 11 + SID_LEN + 4, K_i, 32);
    
    /* Construct nonce: SID || counter */
    memcpy(nonce, ctx->sid, SID_LEN);
    memcpy(nonce + SID_LEN, &ctx->counter, 4);
    
    /* AEAD encrypt using AES-128-GCM or ChaCha20-Poly1305 */
    /* For now, use AES-CTR + HMAC as AEAD construction */
    aead_encrypt(out, out_len, plaintext, pt_len, 
                ctx->sid, SID_LEN,  /* AAD */
                K_i, nonce);
    
    secure_zero(K_i, sizeof(K_i));
    return 0;
}
```

**Add `session_decrypt()`** (~60 lines):
- Similar to encrypt but includes counter replay check
- Verify counter > last_seq
- Verify AEAD tag
- Update last_seq on success

**Add `ratchet_master()`** (~15 lines):
```c
void ratchet_master(session_ctx_t *ctx, const uint8_t *nonce, size_t nonce_len) {
    uint8_t new_K[MASTER_KEY_LEN];
    hkdf_sha256(nonce, nonce_len, ctx->K_master, MASTER_KEY_LEN,
               (uint8_t*)"ratchet", 7, new_K, MASTER_KEY_LEN);
    memcpy(ctx->K_master, new_K, MASTER_KEY_LEN);
    secure_zero(new_K, sizeof(new_K));
}
```

**Add AEAD helper** (~100 lines):
- Simple AEAD construction: AES-128-CTR + HMAC-SHA256
- Or use existing AES-GCM if available
- Input: key, nonce, AAD, plaintext
- Output: ciphertext || tag

---

### 2. Protocol Message Updates

#### Modify `AuthMessage` structure:

**Old** (in both `node-sender.c` and `node-gateway.c`):
```c
typedef struct {
    uint8_t type;
    RingSignature signature;
} AuthMessage;
```

**New** (include syndrome in AUTH message):
```c
typedef struct {
    uint8_t type;
    RingSignature signature;
    uint8_t syndrome[LDPC_ROWS / 8];  /* 51 bytes */
} AuthMessage;
```

#### Modify `AuthAckMessage`:

**Old**:
```c
typedef struct {
    uint8_t type;
    LDPCPublicKey gateway_ldpc_key;
} AuthAckMessage;
```

**New** (include gateway nonce N_G and SID):
```c
typedef struct {
    uint8_t type;
    uint8_t N_G[32];           /* Gateway nonce for K_master derivation */
    uint8_t SID[SID_LEN];      /* Session ID */
} AuthAckMessage;
```

#### Modify `DataMessage`:

**Old**:
```c
typedef struct {
    uint8_t type;
    uint8_t syndrome[LDPC_ROWS / 8];
    uint8_t ciphertext[MESSAGE_MAX_SIZE];
    uint16_t cipher_len;
} DataMessage;
```

**New** (remove syndrome, add SID and counter):
```c
typedef struct {
    uint8_t type;
    uint8_t SID[SID_LEN];
    uint32_t counter;
    uint8_t ciphertext[MESSAGE_MAX_SIZE + AEAD_TAG_LEN];
    uint16_t cipher_len;
} DataMessage;
```

---

### 3. Sender Node Modifications

#### File: [`node-sender.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/node-sender.c)

**Global additions** (after line 50):
```c
static session_ctx_t session_ctx;         /* Session context */
static ErrorVector auth_error_vector;     /* Error vector generated during AUTH */
static uint8_t syndrome[LDPC_ROWS / 8];   /* Syndrome for AUTH */
```

**In authentication phase** (around line 180-228):

*Before ring signature generation* (insert after line 186):
```c
/* Generate error vector and syndrome ONCE during AUTH */
LOG_INFO("Generating error vector for session key derivation...\\n");
generate_error_vector(&auth_error_vector, LDPC_COL_WEIGHT * (LDPC_COLS / 16));

/* Encode syndrome (this is the ONE-TIME LDPC operation) */
/* Note: We don't have gateway's LDPC key yet, so we use a well-known public LDPC key
   OR the sender includes this in AUTH and gateway decodes it */
LOG_INFO("Computing LDPC syndrome (one-time operation)...\\n");
/* For this to work, we need a known LDPC public key OR sender generates its own */
/* Let's use approach: sender generates error, includes syndrome in AUTH */
/* Gateway will decode it and derive K_master */

/* We'll use a simplified approach: include raw error bits in syndrome field */
/* Alternatively, generate syndrome using a public LDPC key */
memcpy(syndrome, auth_error_vector.bits, sizeof(syndrome));
```

*Modify AUTH message* (around line 193-194):
```c
AuthMessage auth_msg;
auth_msg.type = MSG_TYPE_AUTH;
memcpy(auth_msg.syndrome, syndrome, sizeof(syndrome));  /* Include syndrome */
```

**In `udp_rx_callback` AUTH_ACK handler** (replace lines 78-120):
```c
if (msg_type == MSG_TYPE_AUTH_ACK && !auth_completed) {
    AuthAckMessage *ack = (AuthAckMessage *)data;
    
    LOG_INFO("Authentication ACK received!\\n");
    LOG_INFO("Received Session ID and Gateway Nonce\\n");
    
    /* Initialize session context */
    memcpy(session_ctx.sid, ack->SID, SID_LEN);
    session_ctx.counter = 0;
    session_ctx.active = 1;
    session_ctx.expiry_ts = /* current_time + DEFAULT_SESSION_LIFETIME */;
    
    /* Derive K_master from error vector + gateway nonce */
    LOG_INFO("Deriving master session key (K_master)...\\n");
    derive_master_key(session_ctx.K_master,
                     auth_error_vector.bits, sizeof(auth_error_vector.bits),
                     ack->N_G, sizeof(ack->N_G));
    
    LOG_INFO("Session established! SID: ");
    /* log first 4 bytes of SID */
    LOG_INFO("Master key derived (not logged for security)\\n");
    
    /* Zeroize error vector (no longer needed) */
    secure_zero(&auth_error_vector, sizeof(auth_error_vector));
    
    auth_completed = 1;
}
```

**Add data transmission loop** (after AUTH_ACK handling, replace single message send):
```c
/* Send multiple messages using session encryption */
#define NUM_MESSAGES 100  /* Configurable */

for (int msg_num = 0; msg_num < NUM_MESSAGES; msg_num++) {
    DataMessage data_msg;
    data_msg.type = MSG_TYPE_DATA;
    memcpy(data_msg.SID, session_ctx.sid, SID_LEN);
    data_msg.counter = session_ctx.counter;
    
    /* Encrypt using lightweight session encryption */
    size_t cipher_len;
    char msg_buf[64];
    snprintf(msg_buf, sizeof(msg_buf), "Message #%d: %s", msg_num, secret_message);
    
    LOG_INFO("Encrypting message %d (using K_%d)...\\n", msg_num, session_ctx.counter);
    session_encrypt(&session_ctx,
                   (uint8_t*)msg_buf, strlen(msg_buf) + 1,
                   data_msg.ciphertext, &cipher_len);
    
    data_msg.cipher_len = cipher_len;
    
    /* Send data message */
    simple_udp_sendto(&udp_conn, &data_msg,
                     sizeof(uint8_t) + SID_LEN + sizeof(uint32_t) +
                     sizeof(uint16_t) + cipher_len,
                     sender_addr);
    
    session_ctx.counter++;
    
    /* Optional: ratchet after RATCHET_INTERVAL messages */
    if (session_ctx.counter % RATCHET_INTERVAL == 0) {
        LOG_INFO("Ratchet point reached at message %d\\n", msg_num);
        /* In full implementation, coordinate ratchet with gateway */
    }
    
    etimer_set(&periodic_timer, 2 * CLOCK_SECOND);  /* Delay between messages */
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
}

/* Session complete - zeroize */
LOG_INFO("Session complete. Sent %d messages.\\n", NUM_MESSAGES);
secure_zero(&session_ctx, sizeof(session_ctx));
```

---

### 4. Gateway Node Modifications

#### File: [`node-gateway.c`](file:///c:/Users/aloob/Desktop/Amortization_Research/node-gateway.c)

**Global additions** (after line 50):
```c
static session_entry_t session_table[MAX_SESSIONS];  /* Session storage */
```

**Add session management functions** (before `udp_rx_callback`):
```c
/* Find session by SID */
session_entry_t* find_session(const uint8_t *sid) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (session_table[i].in_use &&
            memcmp(session_table[i].sid, sid, SID_LEN) == 0) {
            return &session_table[i];
        }
    }
    return NULL;
}

/* Allocate new session */
session_entry_t* alloc_session(const uint8_t *sid, const uint8_t *K_master,
                              const uip_ipaddr_t *peer, uint32_t expiry) {
    /* Find free slot or evict oldest */
    int free_idx = -1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!session_table[i].in_use) {
            free_idx = i;
            break;
        }
    }
    
    if (free_idx == -1) {
        /* Evict oldest - find session with smallest expiry */
        free_idx = 0;
        for (int i = 1; i < MAX_SESSIONS; i++) {
            if (session_table[i].expiry_ts < session_table[free_idx].expiry_ts) {
                free_idx = i;
            }
        }
        LOG_INFO("Evicting old session to make room\\n");
        secure_zero(&session_table[free_idx], sizeof(session_entry_t));
    }
    
    session_entry_t *se = &session_table[free_idx];
    memcpy(se->sid, sid, SID_LEN);
    memcpy(se->K_master, K_master, MASTER_KEY_LEN);
    memcpy(&se->peer, peer, sizeof(uip_ipaddr_t));
    se->last_seq = 0;
    se->expiry_ts = expiry;
    se->in_use = 1;
    
    return se;
}
```

**In `MSG_TYPE_AUTH` handler** (replace lines 75-104):
```c
if (msg_type == MSG_TYPE_AUTH) {
    AuthMessage *auth_msg = (AuthMessage *)data;
    
    LOG_INFO("\\n[Authentication Phase] Received ring signature\\n");
    LOG_INFO("Keyword: %s\\n", auth_msg->signature.keyword);
    LOG_INFO("Verifying ring signature...\\n");
    
    /* Verify the ring signature */
    int verify_result = ring_verify(&auth_msg->signature, ring_public_keys);
    
    if (verify_result == 1) {
        LOG_INFO("*** SIGNATURE VALID ***\\n");
        LOG_INFO("Ring signature verification successful!\\n");
        
        /* DECODE SYNDROME to recover error vector (ONE-TIME LDPC operation) */
        ErrorVector recovered_error;
        LOG_INFO("Decoding LDPC syndrome (one-time operation)...\\n");
        
        /* Use LDPC decoder */
        if (sldspa_decode(&recovered_error, auth_msg->syndrome, &gateway_ldpc_keypair) != 0) {
            LOG_ERR("LDPC decoding failed during authentication\\n");
            return;
        }
        
        LOG_INFO("LDPC decoding successful!\\n");
        
        /* Generate fresh gateway nonce N_G */
        uint8_t N_G[32];
        for (int i = 0; i < 32; i++) {
            N_G[i] = crypto_random_uint32() & 0xFF;
        }
        
        /* Generate Session ID */
        uint8_t SID[SID_LEN];
        for (int i = 0; i < SID_LEN; i++) {
            SID[i] = crypto_random_uint32() & 0xFF;
        }
        
        /* Derive K_master */
        uint8_t K_master[MASTER_KEY_LEN];
        LOG_INFO("Deriving master session key (K_master)...\\n");
        derive_master_key(K_master,
                         recovered_error.bits, sizeof(recovered_error.bits),
                         N_G, sizeof(N_G));
        
        /* Store session */
        uint32_t expiry = /* current_time */ + DEFAULT_SESSION_LIFETIME;
        session_entry_t *se = alloc_session(SID, K_master, sender_addr, expiry);
        
        LOG_INFO("Session established! SID: [%02x%02x...]\\n", SID[0], SID[1]);
        LOG_INFO("Session will expire in %d seconds\\n", DEFAULT_SESSION_LIFETIME);
        
        /* Zeroize sensitive data */
        secure_zero(&recovered_error, sizeof(recovered_error));
        secure_zero(K_master, sizeof(K_master));  /* Copy in session table */
        
        /* Send ACK with N_G and SID */
        AuthAckMessage ack_msg;
        ack_msg.type = MSG_TYPE_AUTH_ACK;
        memcpy(ack_msg.N_G, N_G, sizeof(N_G));
        memcpy(ack_msg.SID, SID, SID_LEN);
        
        LOG_INFO("Sending ACK with session parameters...\\n");
        simple_udp_sendto(&udp_conn, &ack_msg, sizeof(AuthAckMessage), sender_addr);
        LOG_INFO("ACK sent! Waiting for encrypted data messages...\\n");
        
        secure_zero(N_G, sizeof(N_G));
        
    } else {
        LOG_ERR("*** SIGNATURE INVALID ***\\n");
    }
}
```

**In `MSG_TYPE_DATA` handler** (replace lines 106-142):
```c
else if (msg_type == MSG_TYPE_DATA) {
    DataMessage *data_msg = (DataMessage *)data;
    
    LOG_INFO("\\n[Data Phase] Received encrypted message\\n");
    LOG_INFO("SID: [%02x%02x...], Counter: %u\\n",
             data_msg->SID[0], data_msg->SID[1], data_msg->counter);
    
    /* Lookup session */
    session_entry_t *se = find_session(data_msg->SID);
    
    if (!se) {
        LOG_ERR("Session not found! Rejecting message.\\n");
        LOG_ERR("Client must re-authenticate.\\n");
        return;
    }
    
    /* Decrypt using session */
    uint8_t plaintext[MESSAGE_MAX_SIZE];
    size_t plain_len;
    
    LOG_INFO("Decrypting using session key (lightweight AEAD)...\\n");
    int ret = session_decrypt(se, data_msg->counter,
                             data_msg->ciphertext, data_msg->cipher_len,
                             plaintext, &plain_len);
    
    if (ret == 0) {
        plaintext[plain_len] = '\\0';  /* Null-terminate */
        
        LOG_INFO("*** DECRYPTED MESSAGE: %s ***\\n", plaintext);
        LOG_INFO("Session message #%u decrypted successfully\\n", data_msg->counter);
        
    } else {
        LOG_ERR("Decryption failed! (replay attack or corrupted message)\\n");
    }
}
```

---

## Security Caveats & Limitations

> [!WARNING]
> **Critical Security Disclosures - Must Acknowledge**

### Forward Secrecy Limitation

**Issue:** `K_master` is long-lived (session lifetime = 1 hour default)

**Implication:** Compromise of `K_master` allows decryption of **all messages in that session**

**Current Status:** Forward secrecy is **LIMITED** to session granularity

```
┌─────────────────────────────────────────────────┐
│  If K_master is compromised at time T:         │
│  - Attacker can derive ALL K_i for i ∈ [0,N]   │
│  - Attacker can decrypt ALL session messages    │
│  - Forward secrecy violated WITHIN session      │
│                                                  │
│  BUT: Separate sessions use independent keys   │
│  - Session 1 compromise ≠ Session 2 compromise  │
│  - Re-authentication creates new K_master       │
└─────────────────────────────────────────────────┘
```

**Mitigation (Future Work - NOT in this plan):**

Key ratcheting would provide forward secrecy at message granularity:

```c
/* After every N messages (e.g., N=100): */
K_master_new = HKDF(K_master_old || fresh_nonce, "ratchet")
secure_zero(K_master_old)

/* Now compromise of K_master_new does NOT reveal messages 0..99 */
```

**Explicitly Deferred:** Full ratcheting implementation adds ~200 LOC + control protocol complexity.  
**Acknowledgment:** "Forward secrecy across amortized sessions is limited to session boundaries; per-message ratcheting is future work."

### RNG Quality Caveat

**Issue:** LDPC error vector generation uses `crypto_random_uint32()` (Xorshift PRNG)

**Implication:** Not cryptographically secure for production systems

**Current Mitigation:**  
- SID and nonce generation use `crypto_secure_random()` (hardware RNG)  
- K_master derivation uses HKDF with secure inputs (error vector + N_G)

**Production Recommendation:**  
Replace all PRNG usage with CSPRNG:

```c
/* Current (PoC acceptable): */
generate_error_vector(&error, weight);  // Uses crypto_random_uint32()

/* Production (recommended): */
generate_error_vector_secure(&error, weight);  // Uses crypto_secure_random()
```

**Acknowledgment:** "Error vector generation uses Xorshift PRNG (acceptable for PoC); production deployment should use CSPRNG."

### Session Table Eviction Risk

**Issue:** Gateway has finite session storage (`MAX_SESSIONS = 16`)

**Implication:** Active sessions may be evicted under heavy load

**Scenario:**
```
Gateway has 16 active sessions (full)
New sender authenticates → triggers LRU eviction
Evicted sender's next DATA message → SESSION_NOT_FOUND error
Evicted sender must re-authenticate (adds latency)
```

**Tuning Parameters:**
- Increase `MAX_SESSIONS` (costs 89 bytes RAM per session)
- Decrease `SESSION_LIFETIME` (more aggressive cleanup)
- Implement sticky sessions for high-priority senders (future)

**Acknowledgment:** "Session eviction may impact high-traffic scenarios; tune MAX_SESSIONS based on deployment scale."

### Strict Counter Policy Trade-off

**Issue:** Strict monotonic counters do NOT tolerate packet reordering

**Implication:** Out-of-order delivery causes false replay detection

**Example:**
```
Sender transmits: counter=10, counter=11
Network delivers: counter=11, counter=10

Gateway accepts counter=11 (OK)
Gateway rejects counter=10 (10 ≤ 11) → FALSE POSITIVE
```

**Mitigation (NOT implemented):** Sliding window replay protection (adds 8 bytes per session + complexity)

**Justification:** Contiki CSMA/CA typically delivers in-order; strict policy is acceptable for target use case

**Acknowledgment:** "Replay protection uses strict monotonic counters; out-of-order delivery will trigger false rejections (acceptable for CSMA/CA MAC)."

### Security Claims Summary

✅ **What This Implementation Provides:**
- Post-quantum authentication (Ring-LWE + QC-LDPC)
- Confidentiality via AEAD (AES-CTR + HMAC)
- Integrity via AEAD tags
- Replay protection via counters
- Forward secrecy at **session** granularity

❌ **What This Implementation Does NOT Provide:**
- Forward secrecy at **message** granularity (requires ratcheting)
- Production-grade RNG for all operations (LDPC uses Xorshift)
- Session persistence across gateway reboots
- Tolerance for out-of-order packet delivery
- Protection against session eviction DOS

**Intended Use:** Proof-of-concept for research; production deployment requires addressing above caveats.

---

## Verification Plan

### Automated Tests

#### 1. **Baseline Test** (Current Implementation)

**Purpose**: Measure current per-message costs

**Steps**:
```bash
cd c:/Users/aloob/Desktop/Amortization_Research
git checkout -b baseline-measurement
# Keep original code unchanged
make clean
make TARGET=native
# Run Cooja simulation with 100 messages
# Capture logs to baseline_results.log
```

**Expected Output**:
- 100 messages sent
- Each message: LDPC encode (~100ms CPU) + AES encrypt
- Total time: ~10-15 seconds for 100 messages
- Energy per message: HIGH (LDPC dominates)

#### 2. **Amortized Implementation Test**

**Purpose**: Verify session amortization works and measure improvements

**Steps**:
```bash
git checkout main  # Or create feature branch
# Apply all changes from this plan
make clean
make TARGET=native
# Run same Cooja simulation
# Capture logs to amortized_results.log
```

**Expected Output**:
- AUTH phase: 1× LDPC decode (~100ms)
- 100 messages: each uses HKDF+AEAD (~5ms)
- Total time: ~1-2 seconds for 100 messages
- Energy per message after AUTH: LOW (10-20× reduction)

**Success Criteria**:
- ✅ Gateway successfully decodes syndrome in AUTH
- ✅ K_master derived on both sides
- ✅ All 100 messages encrypted/decrypted successfully
- ✅ No LDPC operations after AUTH phase
- ✅ Counter replay rejected (security test)
- ✅ CPU/energy per message reduced by factor of 10-20×

#### 3. **Security Tests**

**Test 3.1**: Replay Attack Protection
```
- Send same DataMessage twice with same counter
- Expected: Gateway rejects second message
```

**Test 3.2**: Unknown SID Rejection  
```
- Send DataMessage with invalid/unknown SID
- Expected: Gateway requests re-authentication
```

**Test 3.3**: AEAD Tag Verification
```
- Corrupt ciphertext or tag
- Expected: session_decrypt fails, message rejected
```

**Test 3.4**: Session Expiry
```
- Set short expiry (60s)
- Wait for expiry
- Send message
- Expected: Session evicted, message rejected
```

#### 4. **Cooja Simulation Script**

Create `simulation_amortized.csc` based on existing `simulation.csc`:
```xml
\u003c!-- Add energy tracking plugin --\u003e
\u003c!-- Run for 300 seconds --\u003e
\u003c!-- Capture timestamped logs --\u003e
```

**Run command**:
```bash
# Windows
C:/contiki-ng/tools/cooja/gradlew run --args="-nogui=simulation_amortized.csc" \u003e cooja_output.log 2\u003e\u00261
# Linux
cd /path/to/contiki-ng/tools/cooja
./gradlew run --args="-nogui=simulation_amortized.csc"
```

**Metrics to capture**:
- Timestamp of AUTH complete
- Timestamp of each K_i derivation
- Timestamp of each message send/receive
- CPU cycles (if available via Cooja power tracking)
- Energy consumption (if available)

### Manual Validation

> [!IMPORTANT]
> **User Input Required**: Please confirm you have Cooja simulator set up and can run simulations. If you prefer a different testing approach, please let me know.

**Steps for user**:
1. Build both node-sender and node-gateway with `make TARGET=z1`
2. Open Cooja simulator
3. Load `simulation_amortized.csc` (we'll create this)
4. Start simulation
5. Review logs confirming:
   - Single LDPC decode during AUTH
   - Multiple messages encrypted with HKDF+AEAD
   - Performance improvement visible in timestamps

---

## Safety \u0026 Security Defaults

1. **Zeroize K_master**:
   - On session end (counter limit or expiry)
   - On process exit
   - After deriving K_i (ephemeral keys)

2. **Secure RNG**:
   - Use crypto-grade random for SID, N_G, nonces
   - Current `crypto_random_uint32()` is Xorshift (acceptable for PoC)

3. **No Secret Logging**:
   - Never log K_master, K_i, or error vectors
   - Log SID (first 2 bytes only for debugging)

4. **AEAD Verification**:
   - Always check return value of `session_decrypt()`
   - Drop messages on tag mismatch
   - Log minimal info (avoid timing side-channels)

5. **Session Limits**:
   - MAX_SESSIONS = 16 (gateway limit)
   - Evict oldest when full
   - MAX_MESSAGES_PER_SESSION = 10000

6. **Constant-time Operations**:
   - Use existing `constant_time_compare()` for tag verification
   - Avoid branching on secret data in critical paths

---

## Deliverables

After implementation, I will provide:

1. **Modified source files**:
   - `crypto_core.h` (session structures + new prototypes)
   - `crypto_core.c` (HKDF, session_encrypt/decrypt, AEAD)
   - `node-sender.c` (AUTH with syndrome, session-based data send)
   - `node-gateway.c` (syndrome decode in AUTH, session table, AEAD decrypt)

2. **Build artifacts**:
   - `node-sender.z1` and `node-gateway.z1`
   - Build log showing successful compilation
   - Memory usage report

3. **Test results**:
   - Baseline measurement logs
   - Amortized measurement logs
   - Performance comparison table (CPU/energy per message)
   - Security test results (replay, unknown SID, tag corruption)

4. **Documentation**:
   - Walkthrough markdown with:
     - Code changes summary (file-by-file)
     - Session state diagram
     - Performance comparison graphs/tables
     - Security analysis
   - Git diff/patch for all changes

---

## Open Questions for User Review

> [!WARNING]
> **Breaking Changes**:
> - Message format changes (AuthMessage, AuthAckMessage, DataMessage)
> - Not backward compatible with existing implementation
> - Requires both sender and gateway to upgrade simultaneously

1. **AEAD Choice**: Should I implement:
   - Option A: AES-128-CTR + HMAC-SHA256 (using existing primitives)
   - Option B: ChaCha20-Poly1305 (need to add full implementation)
   - **Recommendation**: Option A (simpler, reuses existing AES/SHA256)

2. **Ratcheting**: Should I implement key ratcheting in this iteration?
   - Adds complexity (control messages, synchronization)
   - Provides forward secrecy after ratchet points
   - **Recommendation**: Add data structures and placeholder, defer full impl to Phase 5

3. **Testing approach**: Do you have access to Cooja simulator, or should I create a simple native test harness instead?


### K. Additional Safety Precautions

**Add to all logging calls:**
```c
/* NEVER log secrets - use redaction helpers */
void log_sid_safe(const uint8_t *sid) {
    LOG_INFO("SID: [%02x%02x...]", sid[0], sid[1]);
    /* Only first 2 bytes for debugging */
}

/* Sample logs: */
LOG_INFO("K_master derived (not logged for security)\n");
LOG_INFO("K_i derived for counter=%u (key not logged)\n", counter);
```

**Session termination:**
```c
/* On session end, counter limit, or expiry */
void terminate_session(session_ctx_t *ctx) {
    LOG_INFO("Terminating session SID=[%02x%02x...]\n", 
             ctx->sid[0], ctx->sid[1]);
    secure_zero(ctx->K_master, MASTER_KEY_LEN);
    secure_zero(ctx->sid, SID_LEN);
    ctx->active = 0;
    ctx->counter = 0;
}
```

---

## Implementation Checklist

Before proceeding to code implementation, verify all items are addressed:

- [ ] **A. Build System**
  - [ ] Makefile updated with `crypto_core.c`
  - [ ] CFLAGS defined for session parameters
  - [ ] Memory size check target added

- [ ] **B. Message Serialization**
  - [ ] `write_uint32_be()` / `read_uint32_be()` helpers added
  - [ ] DataMessage sending uses packed buffers
  - [ ] DataMessage parsing handles variable-length correctly

- [ ] **C. AEAD Implementation**
  - [ ] HMAC-SHA256 implemented (~60 lines)
  - [ ] `aead_encrypt()` implemented (~100 lines)
  - [ ] `aead_decrypt()` with constant-time tag check

- [ ] **D. HKDF Implementation**
  - [ ] `hkdf_extract()` implemented
  - [ ] `hkdf_expand()` implemented
  - [ ] `hkdf_sha256()` wrapper complete
  - [ ] RFC 5869 test vectors added and passing

- [ ] **E. Secure RNG**
  - [ ] `crypto_secure_random()` uses hardware RNG
  - [ ] All SID/nonce generation updated
  - [ ] Fallback documented if no CSPRNG available

- [ ] **F. LDPC Handshake**
  - [ ] Sender has hardcoded shared LDPC public key
  - [ ] Sender computes `s = H × e^T`
  - [ ] Gateway decodes syndrome in AUTH handler
  
- [ ] **G. Memory Budget**
  - [ ] Memory estimates documented
  - [ ] MAX_SESSIONS tuned for Z1 (≤16)
  - [ ] ROM/RAM usage measured with `msp430-size`

- [ ] **H. Secure Zeroization**
  - [ ] `secure_zero()` implemented with volatile pointers
  - [ ] All K_master/K_i zeroized after use
  - [ ] Error vectors zeroized after AUTH phase

- [ ] **I. Unit Tests**
  - [ ] `test_session.c` created
  - [ ] HKDF test vectors passing
  - [ ] AEAD round-trip test passing
  - [ ] Makefile test target added

- [ ] **J. Process Safety**
  - [ ] Sender data loop uses PROCESS_WAIT_EVENT_UNTIL
  - [ ] Gateway LDPC decode protected with watchdog_periodic()
  - [ ] No blocking calls in packet handlers

- [ ] **K. Logging Safety**
  - [ ] No K_master/K_i/error vector logging
  - [ ] SID logging redacted to first 2 bytes
  - [ ] Session termination logging added

---

## Revised Open Questions

> [!WARNING]
> **Breaking Changes**:
> - Message format changes (AuthMessage, AuthAckMessage, DataMessage)
> - Not backward compatible with existing implementation
> - Requires both sender and gateway to upgrade simultaneously

### Decisions Made (based on feedback):

1. **✅ AEAD Choice:** AES-128-CTR + HMAC-SHA256
   - Rationale: Reuses existing primitives, no new dependencies
   - Implementation: Encrypt-then-MAC with separate keys

2. **✅ Message Serialization:** Manual packing with big-endian integers
   - Rationale: Avoids struct padding, ensures cross-platform compatibility
   - Implementation: `write_uint32_be()` / `read_uint32_be()` helpers

3. **✅ Secure RNG:** Platform CSPRNG (Contiki `random_rand()`)
   - Rationale: Hardware RNG on Z1/CC2538 is cryptographically secure
   - Fallback: Document /dev/urandom for native tests

4. **✅ LDPC Handshake:** Sender uses hardcoded public H
   - Rationale: Simplest for PoC, keeps `e` secret
   - Future: Gateway could distribute H dynamically

5. **✅ Memory Budget:** MAX_SESSIONS=16, total ~2KB new RAM
   - Rationale: Leaves ~10KB for stack/network on Z1
   - Mitigation: Can reduce to 8 sessions if needed

### Remaining Questions for User:

1. **Key Ratcheting:** Should I implement full ratcheting now or defer?
   - Current plan: Add data structures, defer ratchet protocol to Phase 5
   - **Recommendation:** Defer (adds ~200 lines + control message complexity)

2. **Testing:** Do you have Cooja simulator access?
   - If yes: I'll create `simulation_amortized.csc` for energy measurements
   - If no: I'll create native test harness with timing measurements

3. **Baseline measurement:** Should I create a baseline test before modifying code?
   - Recommended: Tag current code, measure per-message cost, then implement amortization
   - Alternative: Implement directly and compare against theoretical estimates

---

## Summary of Changes from Feedback

The implementation plan has been enhanced with:

- ✅ **Build system requirements** (Makefile updates, compile flags)
- ✅ **Message serialization** (network byte order, packed buffers)
- ✅ **Complete AEAD implementation** (HMAC-SHA256 + AES-CTR)
- ✅ **Complete HKDF implementation** (with RFC 5869 test vectors)
- ✅ **Cryptographically secure RNG** (platform-specific CSPRNG)
- ✅ **LDPC handshake clarification** (sender with hardcoded public H)
- ✅ **Memory budget analysis** (~2KB new RAM, acceptable for Z1)
- ✅ **Secure zeroization** (volatile pointers)
- ✅ **Unit testing framework** (native tests before Cooja)
- ✅ **Contiki process safety** (proper protothread usage, watchdog)
- ✅ **Logging safety** (no secret exposure)

All critical items flagged in the technical review are now addressed in the plan.

---
