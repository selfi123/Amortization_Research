# Research Workflow: Chronological Deep Dive

This document explains the exact step-by-step execution of your two research approaches.

---

## 1. Baseline: "Without Amortization"
**Philosophy**: "New pad for every message." (Hybrid Encryption per packet)

### Chronological Flow

| Phase | Time | Technical Action | Simple Explanation | Example Values |
| :--- | :--- | :--- | :--- | :--- |
| **1. Auth** | T=0s | **Sender**: `ring_lwe_keygen()` | Sender generates keys to prove identity. | `Pk_sender` (2KB) |
| | T=1s | **Sender**: `ring_sign(msg="AUTH")` | Sender creates a math puzzle (Signature) that only a ring member could solve. | `Signature` (6KB) |
| | T=1.1s | **Network**: Transmit `[Signature]` | Sending the heavy signature. | `Payload: 6144 bytes` |
| | T=1.2s | **Gateway**: `ring_verify()` | Gateway checks if the signature is valid. | `Result: VALID` |
| | T=1.3s | **Network**: Transmit `[LDPCPublicKey]` | Gateway sends an encryption map (Matrix H) to Sender. | `PubKey` (1KB) |
| **2. Data** | T=2s | **Sender**: `generate_error_vector()` | Sender picks a **new random secret number** (`e`) for this specific message. | `e1` (Weight 50) |
| | | **Sender**: `ldpc_encode(e)` | Sender calculates the "hint" (Syndrome) for this secret. | `Syndrome_1` (51 bytes) |
| | | **Sender**: `Hash(e) XOR Message` | Encrypts message using the secret `e`. | `Ciphertext_1` |
| | | **Network**: Transmit `[Syndrome | Ciphertext]` | Sends the hint and the locked message. | `Payload: 51 + 20 = 71 bytes` |
| | | **Gateway**: `sldspa_decode(Syndrome)` | Gateway uses the map (Matrix H) and the hint to utilize CPU to find `e`. **Heavy Work.** | `Recovered: e1` |
| | | **Gateway**: `Hash(e) XOR Cipher` | Unlocks the message. | `Msg: "Hello #1"` |
| **3. Data** | T=3s | **Sender**: `generate_error_vector()` | **REPEAT**: Sender picks a **NEW** random secret (`e2`). | `e2` (Weight 50) |
| | | **Network**: Transmit `[Syndrome2 | Ciphertext2]` | Sends new hint and new message. | `Payload: 71 bytes` |
| | | **Gateway**: `sldspa_decode(Syndrome2)` | **REPEAT**: Gateway must do heavy decoding again. | `Recovered: e2` |

**Summary**: High CPU load for *every* message (Gateway) and High Bandwidth overhead (Syndrome sent every time).

---

## 2. Proposed: "Amortization Research"
**Philosophy**: "Agree on a secret once, use it forever." (Session Key)

### Chronological Flow

| Phase | Time | Technical Action | Simple Explanation | Example Values |
| :--- | :--- | :--- | :--- | :--- |
| **1. Auth** | T=0s | **Sender**: `ring_sign("AUTH")` | Same as baseline: generate identity proof. | `Signature` (6KB) |
| | | **Sender**: `generate_error_vector()` | Sender picks a **Master Secret (`e`)** to use for the *entire* conversation. | `e_master` (Weight 50) |
| | | **Sender**: `ldpc_encode(e)` | Calculates the "hint" (Syndrome) for the Master Secret. | `Syndrome_Master` (51 bytes) |
| | T=1.1s | **Network**: Transmit `[Signature | Syndrome]` | Sends proof AND the key hint in one go. | `Payload: 6195 bytes` |
| | T=1.2s | **Gateway**: `ring_verify()` + `sldspa_decode()` | Gateway verifies identity AND recovers the Master Secret `e` **ONCE**. | `Recovered: e_master` |
| | | **Gateway**: `K_master = SHA256(e)` | Gateway saves this key in a table. | `SID: 0xAB12...` |
| | T=1.3s | **Network**: Transmit `[SID | Nonce]` | Gateway says "I know the secret. Here is your Session ID." | `Msg: ACK` |
| **2. Data** | T=2s | **Sender**: `AES_Encrypt(K_master, Msg)` | Sender uses the *existing* secret to lock the message. **Fast.** | `K_session` |
| | | **Network**: Transmit `[SID | Ciphertext]` | Sends ONLY the ID and locked message. **No Syndrome!** | `Payload: 8 + 20 = 28 bytes` |
| | | **Gateway**: `Lookup(SID)` -> `AES_Decrypt()` | Gateway looks up the key and unlocks. **Fast.** | `Msg: "Hello #1"` |
| **3. Data** | T=3s | **Sender**: `AES_Encrypt(K_master, Msg2)` | **REPEAT**: Reuses the secret. No math, just fast locking. | `K_session` (rotated) |
| | | **Network**: Transmit `[SID | Ciphertext2]` | **Efficient**: Minimal packet size. | `Payload: 28 bytes` |
| | | **Gateway**: `Lookup` -> `Decrypt` | **REPEAT**: Fast lookup. No heavy decoding. | `Msg: "Hello #2"` |

## Comparison Summary

| Attribute | Without Amortization | With Amortization | Why it matters? |
| :--- | :--- | :--- | :--- |
| **Sender CPU** | High (Matrix Mult per packet) | Low (AES per packet) | Battery life on IoT Sensor |
| **Gateway CPU** | **Very High** (Decoding per packet) | Low (AES per packet) | Gateway can handle 1000x more sensors |
| **Network Size** | 71 bytes / packet | 28 bytes / packet | **60% Bandwidth Saving** |
| **Security** | Perfect Forward Secrecy (New key always) | Session Security (Key rotation) | Amortization trades slight PFS for huge performance |

### Code Mapping
*   **Without Amortization**: Look at `hybrid_encrypt` call inside the loop in `node-sender.c`.
*   **With Amortization**: Look at `session_encrypt` call inside the loop in `node-sender.c`. It uses `session_ctx` instead of generating a new LDPC vector.
