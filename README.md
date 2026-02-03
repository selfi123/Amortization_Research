# Post-Quantum Cryptography for Contiki-NG IoT Devices

Implementation of "A post-quantum lattice based lightweight authentication and code-based hybrid encryption scheme for IoT devices" by Kumari et al. for resource-constrained IoT devices using Contiki-NG OS.

## 🔐 Overview

This project implements two post-quantum cryptographic schemes:

1. **LR-IoTA Authentication**: Ring-LWE based ring signature (N=3 members) with Bernstein reconstruction for polynomial multiplication
2. **QC-LDPC Hybrid Encryption**: Code-based encryption with SLDSPA decoding combined with AES-128 session encryption

## 📊 Parameters (Table 2 from Paper)

| Parameter | Description | Value |
|-----------|-------------|-------|
| n | Polynomial degree | 512 |
| q | Modulus | 2^29 - 3 (536870909) |
| σ | Standard deviation | 43 |
| E | Bound | 2^21 - 1 |
| N | Ring size | 3 |
| X | LDPC rows | 408 |
| Y | LDPC columns | 816 |

## 📁 Project Structure

```
My_Research/
├── project-conf.h       # Contiki-NG configuration
├── crypto_core.h        # Cryptographic function declarations
├── crypto_core.c        # Complete crypto implementation (2000+ lines)
├── node-sender.c        # Sender/initiator node
├── node-gateway.c       # Gateway/receiver node
├── Makefile            # Build system
└── README.md           # This file
```

## 🚀 Quick Start

### Prerequisites

1. **Contiki-NG**: Clone from https://github.com/contiki-ng/contiki-ng
2. **Toolchain**: 
   - For native testing: GCC
   - For Z1 mote: `msp430-gcc` toolchain

### Build Instructions

1. **Edit Makefile**: Set the `CONTIKI` variable to your Contiki-NG installation path:
   ```makefile
   CONTIKI = /home/user/contiki-ng
   ```

2. **Build for native testing**:
   ```bash
   make TARGET=native
   ```

3. **Build for Z1 mote**:
   ```bash
   make TARGET=z1
   ```

4. **Check memory usage**:
   ```bash
   make size TARGET=z1
   ```

### Running in Cooja Simulator

1. **Build the firmware**:
   ```bash
   make TARGET=z1
   ```

2. **Open Cooja**:
   ```bash
   cd /path/to/contiki-ng/tools/cooja
   ant run
   ```

3. **Create new simulation**:
   - File → New Simulation
   - Add Z1 mote type → Browse to `node-gateway.z1`
   - Add another Z1 mote type → Browse to `node-sender.z1`
   - Place one gateway and one sender mote
   - Start simulation

4. **View output**:
   - Right-click mote → Mote output
   - Watch authentication and encryption protocol execute

## 🔄 Protocol Flow

### Phase 1: Ring-LWE Authentication

**Sender:**
1. Generates Ring-LWE key pair (sk, pk, R)
2. Simulates other ring members (generates their public keys)
3. Creates ring signature on keyword "AUTH_REQUEST"
4. Sends {S₁, S₂, S₃, keyword} to gateway

**Gateway:**
1. Receives ring signature
2. Verifies using Bernstein polynomial multiplication (w = S - T·ζ mod q)
3. If valid, sends ACK **with LDPC public key**

### Phase 2: LDPC Hybrid Encryption

**Sender:**
1. Receives ACK containing gateway's LDPC public key
2. Generates random error vector e (low Hamming weight)
3. Encodes syndrome = H·eᵀ
4. Derives session key ssk = SHA256(e)
5. Encrypts message with AES-128-CTR using ssk
6. Sends {syndrome, ciphertext}

**Gateway:**
1. Receives encrypted data
2. Decodes syndrome using SLDSPA to recover error vector e
3. Derives session key ssk = SHA256(e)
4. Decrypts ciphertext with AES-128
5. Displays plaintext message

## 🧮 Algorithm Implementations

### Bernstein Reconstruction (Algorithm 3)

Recursive Karatsuba polynomial multiplication without NTT:
- Splits polynomials into low/high halves
- Recursively computes C₀ = A₀·B₀, C₂ = A₁·B₁, C₁ = (A₀+A₁)·(B₀+B₁)
- Reconstructs: Result = C₀ + (C₁-C₀-C₂)·x^(n/2) + C₂·x^n
- Base case: schoolbook multiplication for degree ≤ 8

### SLDSPA Decoder (Algorithm 6)

Simplified Log-Domain Sum-Product Algorithm:
- Min-Sum approximation for check node updates
- Avoids hyperbolic tangent (tanh) calculations
- Check node: Lc ≈ ∏sign(L) × min(|L|)
- Variable node: Standard sum of incoming messages
- Hard decision threshold with syndrome verification

## 💾 Memory Considerations

**Per-polynomial storage**: 512 × 4 bytes = 2 KB

**Z1 Mote constraints**:
- RAM: 16 KB total
- ROM: 92 KB total

**Optimizations applied**:
- Static global buffers for polynomial operations (avoid stack overflow)
- Compressed LDPC matrix representation (seed + circulant shifts)
- On-the-fly matrix generation
- No floating-point arithmetic

## 🔧 Customization

### Changing Ring Size

Edit `crypto_core.h`:
```c
#define RING_SIZE 5  // Change from 3 to 5 members
```

### Changing Security Parameters

Edit the parameter defines in `crypto_core.h`:
```c
#define POLY_DEGREE 1024     // Higher security
#define STD_DEVIATION 50     // Adjust Gaussian width
```

**Note**: Increasing parameters will increase memory usage!

## 🧪 Testing & Validation

### Expected Output - Gateway
```
=== Post-Quantum Gateway Node Starting ===
[Initialization] Generating cryptographic keys...
Ring-LWE key generation: SUCCESS
LDPC matrix generation: SUCCESS
=== Gateway Ready ===
Listening for incoming connections...

[Authentication Phase] Received ring signature
*** SIGNATURE VALID ***
Sending ACK with LDPC public key...

[Data Phase] Received encrypted message
LDPC decoding successful!
========================================
*** DECRYPTED MESSAGE: Hello IoT ***
========================================
```

### Expected Output - Sender
```
=== Post-Quantum Sender Node Starting ===
[Phase 1] Generating Ring-LWE keys...
Ring-LWE key generation successful

[Phase 2] Starting Ring Signature Authentication...
Ring signature generated successfully
Sending authentication packet to gateway...

Authentication ACK received!
Proceeding to encrypted data transmission...
Encrypted message 'Hello IoT'
Data transmission complete!
=== PROTOCOL COMPLETE ===
```

## 📚 Implementation Details

### Cryptographic Primitives

| Primitive | Implementation | Lines of Code |
|-----------|---------------|---------------|
| Bernstein Multiplication | Recursive Karatsuba | ~80 |
| Ring-LWE KeyGen | Rejection sampling | ~50 |
| Ring Signature | Algorithm 3 | ~150 |
| LDPC Encoding | Circulant matrix | ~40 |
| SLDSPA Decoder | Min-sum approximation | ~100 |
| SHA-256 | Lightweight | ~120 |
| AES-128 | CTR mode | ~200 |

### Protocol Messages

**AuthMessage** (Authentication):
```c
struct {
    uint8_t type;              // MSG_TYPE_AUTH
    RingSignature signature;   // {S1, S2, S3, keyword}
}
```

**AuthAckMessage** (ACK with key):
```c
struct {
    uint8_t type;               // MSG_TYPE_AUTH_ACK
    LDPCPublicKey gateway_key;  // Gateway's LDPC public key
}
```

**DataMessage** (Encrypted data):
```c
struct {
    uint8_t type;               // MSG_TYPE_DATA
    uint8_t syndrome[51];       // LDPC syndrome (408 bits)
    uint8_t ciphertext[64];     // AES encrypted message
    uint16_t cipher_len;        // Length of ciphertext
}
```

## ⚠️ Important Notes

1. **ACK Handshake**: The gateway MUST send its LDPC public key in the ACK. This is critical for the sender to encrypt data.

2. **Ring Members**: The sender simulates other ring members. In production, these would be real network nodes.

3. **Pseudo-Random Generator**: Uses Xorshift for embedded efficiency. For production, use a CSPRNG.

4. **Gaussian Sampling**: Uses Box-Muller approximation. Can be improved with discrete Gaussian tables.

5. **LDPC Matrix**: Stored as seed + shift indices, not full matrix, to save ~42 KB of RAM.

## 🐛 Troubleshooting

**Compilation fails with "field exceeds size"**:
- Reduce `POLY_DEGREE` or use native target instead of Z1

**Signature verification fails**:
- Check that all ring members' public keys are correctly initialized
- Verify modular arithmetic is using same modulus q

**LDPC decoding doesn't converge**:
- Increase `max_iterations` in `sldspa_decode()`
- Reduce error vector weight
- Check syndrome computation

**Out of memory on Z1**:
- Test with native target first
- Reduce number of ring members
- Optimize static buffer usage

## 📖 References

- Kumari et al., "A post-quantum lattice based lightweight authentication and code-based hybrid encryption scheme for IoT devices"
- Bernstein, D.J., "Curve25519: New Diffie-Hellman Speed Records"
- Contiki-NG Documentation: https://docs.contiki-ng.org/

## 📄 License

This implementation is provided for research and educational purposes.

## 👥 Authors

Implementation based on the research paper by Kumari et al.
Code implementation for Contiki-NG by research team.

---

**Status**: ✅ Complete, compilable, no placeholders
**Target**: Z1 mote & Native
**Language**: C (ISO C99)
**Dependencies**: Contiki-NG OS
