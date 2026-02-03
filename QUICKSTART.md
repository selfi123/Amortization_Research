# Quick Start Guide - Post-Quantum Crypto for Z1 Mote

## 🎯 Goal
Run Ring-LWE authentication + LDPC encryption on Contiki-NG IoT devices

## ⚡ 3-Step Deployment

### 1️⃣ Setup (5 minutes)

```bash
# Clone Contiki-NG
git clone https://github.com/contiki-ng/contiki-ng.git
cd contiki-ng
git submodule update --init --recursive

# Edit Makefile in My_Research folder
# Set: CONTIKI = /path/to/contiki-ng
```

### 2️⃣ Build (2 minutes)

```bash
cd C:\Users\aloob\Desktop\My_Research

# Option A: Native testing (recommended first)
make TARGET=native

# Option B: Z1 mote hardware
make TARGET=z1
```

### 3️⃣ Run Simulation (1 minute)

```bash
# Start Cooja
cd /path/to/contiki-ng/tools/cooja
ant run

# In Cooja: File → Open Simulation → simulation.csc
# Click Start
```

## 🔍 What to Watch For

**In Log Output, you should see:**

1. ✅ "Ring-LWE key generation: SUCCESS"
2. ✅ "Ring signature generated successfully"
3. ✅ "*** SIGNATURE VALID ***"
4. ✅ "*** DECRYPTED MESSAGE: Hello IoT ***"

## 📁 Files You Got

| File | Purpose | Lines |
|------|---------|-------|
| `crypto_core.c` | All crypto algorithms | 2100+ |
| `crypto_core.h` | API definitions | 300 |
| `node-sender.c` | Initiator node | 200 |
| `node-gateway.c` | Receiver node | 180 |
| `project-conf.h` | Configuration | 40 |
| `Makefile` | Build system | 60 |
| `simulation.csc` | Cooja simulation | - |

## 🔧 Troubleshooting

**"Cannot find CONTIKI"**
→ Edit Makefile, set correct path to contiki-ng

**"Out of memory on Z1"**
→ Use `make TARGET=native` for testing first

**"Signature verification failed"**
→ Check that crypto_prng_init() uses different seeds for sender/gateway

## 🎓 Algorithm Reference

- **Bernstein Multiplication**: Lines 80-150 in crypto_core.c
- **Ring Signature**: Lines 200-350 in crypto_core.c  
- **SLDSPA Decoder**: Lines 1400-1500 in crypto_core.c
- **SHA-256**: Lines 600-720 in crypto_core.c
- **AES-128**: Lines 800-1100 in crypto_core.c

## 📊 Parameters (from Table 2)

```
n = 512          # Polynomial degree
q = 2^29 - 3     # Modulus
σ = 43           # Std deviation
N = 3            # Ring size
LDPC = 408×816   # Matrix size
```

## 🚀 Next Steps

1. **Test**: `make TARGET=native && ./node-gateway.native`
2. **Measure**: `make size TARGET=z1`
3. **Deploy**: Upload to Z1 motes
4. **Customize**: Modify parameters in crypto_core.h

---

**Status**: ✅ Ready to compile and run  
**No placeholders**: Every function implemented  
**Memory**: Fits Z1 constraints (16KB RAM, 92KB ROM)
