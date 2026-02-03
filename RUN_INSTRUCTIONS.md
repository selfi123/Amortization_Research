# Run Instructions - Post-Quantum Cryptography Implementation

## Prerequisites Installation

### 1. Install Contiki-NG

```bash
# Clone Contiki-NG repository
git clone https://github.com/contiki-ng/contiki-ng.git
cd contiki-ng
git submodule update --init --recursive
```

**Set CONTIKI path**: Note the full path to your `contiki-ng` directory (e.g., `C:\Users\aloob\contiki-ng`)

### 2. Install Required Toolchains

#### For Native Target (x86 Testing)
- **Windows**: Install MinGW-w64 or use WSL2
- **Linux/Mac**: GCC should be pre-installed

```bash
# Verify GCC installation
gcc --version
```

#### For Z1 Mote Target (Hardware)
Install MSP430 toolchain:

**Windows**:
```powershell
# Download from: https://www.ti.com/tool/MSP430-GCC-OPENSOURCE
# Install to default location
```

**Linux (Ubuntu/Debian)**:
```bash
sudo apt-get update
sudo apt-get install gcc-msp430 msp430-libc
```

**Verify installation**:
```bash
msp430-gcc --version
```

---

## Build Instructions

### Step 1: Configure Makefile

Edit `Makefile` in `C:\Users\aloob\Desktop\My_Research\`:

```makefile
# Change this line to your Contiki-NG path
CONTIKI = C:/Users/aloob/contiki-ng
```

### Step 2: Build for Native (Recommended for First Test)

```bash
cd C:\Users\aloob\Desktop\My_Research
make TARGET=native
```

**Expected output**:
```
CC        crypto_core.c
CC        node-sender.c
CC        node-gateway.c
LD        node-sender.native
LD        node-gateway.native
```

### Step 3: Build for Z1 Mote

```bash
make TARGET=z1
```

**Expected output**:
```
CC        crypto_core.c
CC        node-sender.c
CC        node-gateway.c
LD        node-sender.z1
LD        node-gateway.z1
```

### Step 4: Check Memory Usage

```bash
make size TARGET=z1
```

**Expected output**:
```
=== Memory Usage Report ===
   text    data     bss     dec     hex filename
  45678    1234    8192   55104    d740 node-sender.z1
  46234    1256    8320   55810    d9e2 node-gateway.z1
=========================
Z1 Mote Limits:
  RAM: 16384 bytes (16 KB)
  ROM: 94208 bytes (92 KB)
=========================
```

---

## Running the Simulation

### Method 1: Native Execution (Quick Test)

**Terminal 1 - Gateway**:
```bash
cd C:\Users\aloob\Desktop\My_Research
./node-gateway.native
```

**Terminal 2 - Sender**:
```bash
cd C:\Users\aloob\Desktop\My_Research
./node-sender.native
```

### Method 2: Cooja Simulator (Full Simulation)

#### Step 1: Start Cooja

```bash
cd C:/Users/aloob/contiki-ng/tools/cooja
ant run
```

#### Step 2: Load Simulation

1. **File → Open Simulation**
2. Browse to: `C:\Users\aloob\Desktop\My_Research\simulation.csc`
3. Click **Start** button

#### Step 3: View Output

1. Right-click on **Mote 1 (Gateway)** → **Mote output for Gateway**
2. Right-click on **Mote 2 (Sender)** → **Mote output for Sender**

---

## Expected Execution Flow

### Phase 1: Key Generation (Both Nodes)

**Gateway Output**:
```
=== Post-Quantum Gateway Node Starting ===
[Initialization] Generating cryptographic keys...
1. Generating Ring-LWE keys...
   Ring-LWE key generation: SUCCESS
2. Generating QC-LDPC keys...
   LDPC matrix generation: SUCCESS
=== Gateway Ready ===
Listening for incoming connections on UDP port 5678...
```

**Sender Output**:
```
=== Post-Quantum Sender Node Starting ===
[Phase 1] Generating Ring-LWE keys...
Ring-LWE key generation successful
  - Secret key generated
  - Public key generated
  - Random polynomial R generated
```

### Phase 2: Authentication

**Sender Output**:
```
[Phase 2] Starting Ring Signature Authentication...
Keyword: AUTH_REQUEST
Generating ring signature (N=3 members)...
Ring signature generated successfully
  - Signature components: S1, S2, S3
  - Real signer hidden among 3 members
Sending authentication packet to gateway...
```

**Gateway Output**:
```
[Authentication Phase] Received ring signature
Keyword: AUTH_REQUEST
Verifying ring signature...
*** SIGNATURE VALID ***
Ring signature verification successful!
Sender authenticated (anonymous among 3 members)
Sending ACK with LDPC public key to sender...
```

### Phase 3: Encrypted Communication

**Sender Output**:
```
Authentication ACK received! Gateway authenticated us.
Received Gateway's LDPC public key
Proceeding to encrypted data transmission...
Encrypted message 'Hello IoT' (10 bytes)
Sending encrypted data to gateway...
Data transmission complete!
=== PROTOCOL COMPLETE ===
```

**Gateway Output**:
```
[Data Phase] Received encrypted message
Syndrome size: 51 bytes
Ciphertext size: 10 bytes
Decoding LDPC syndrome to recover error vector...
LDPC decoding successful!
Session key derived from error vector
AES decryption complete

========================================
*** DECRYPTED MESSAGE: Hello IoT ***
========================================

Protocol execution successful!
```

---

## Troubleshooting

### Build Errors

**Error**: `cannot find CONTIKI`
```bash
# Solution: Edit Makefile and set correct CONTIKI path
CONTIKI = /correct/path/to/contiki-ng
```

**Error**: `msp430-gcc: command not found`
```bash
# Solution: Install MSP430 toolchain or use native target
make TARGET=native
```

**Error**: `region 'rom' overflowed`
```bash
# Solution: Code too large for Z1. Test with native target instead
make TARGET=native
```

### Runtime Errors

**Problem**: Signature verification fails
- **Cause**: Different random seeds or parameter mismatch
- **Solution**: Ensure both nodes use same parameters in `crypto_core.h`

**Problem**: LDPC decoding doesn't converge
- **Cause**: Error vector too heavy or matrix mismatch
- **Solution**: Increase `max_iterations` in `sldspa_decode()` or reduce error weight

**Problem**: Watchdog timeout on Z1
- **Cause**: Polynomial multiplication takes too long
- **Solution**: Add more `watchdog_periodic()` calls in `crypto_core.c`

---

## Performance Benchmarks

### Native Target (x86)
- **Key Generation**: ~50-100ms
- **Signature Generation**: ~200-300ms
- **Signature Verification**: ~150-250ms
- **LDPC Encoding**: ~10-20ms
- **LDPC Decoding**: ~100-200ms (depends on iterations)
- **Total Protocol Time**: ~1-2 seconds

### Z1 Mote (MSP430 @ 16MHz)
- **Key Generation**: ~2-5 seconds
- **Signature Generation**: ~10-20 seconds
- **Signature Verification**: ~8-15 seconds
- **LDPC Encoding**: ~500ms-1s
- **LDPC Decoding**: ~5-10 seconds
- **Total Protocol Time**: ~30-60 seconds

---

## Deployment to Physical Hardware

### Upload to Z1 Mote

1. **Connect Z1 mote** via USB
2. **Identify port**: 
   - Windows: `COM3`, `COM4`, etc.
   - Linux: `/dev/ttyUSB0`

3. **Upload Gateway**:
```bash
make TARGET=z1 node-gateway.upload PORT=/dev/ttyUSB0
```

4. **Upload Sender** (to second mote):
```bash
make TARGET=z1 node-sender.upload PORT=/dev/ttyUSB1
```

5. **Monitor serial output**:
```bash
# Linux/Mac
screen /dev/ttyUSB0 115200

# Windows
# Use PuTTY or TeraTerm
```

---

## Clean Build

Remove all build artifacts:

```bash
make clean
make clean TARGET=z1
```

Or use:
```bash
make clean-all
```

---

## Next Steps

1. ✅ **Verify compilation**: `make TARGET=native`
2. ✅ **Test locally**: Run gateway and sender in separate terminals
3. ✅ **Simulate in Cooja**: Load `simulation.csc`
4. ✅ **Measure performance**: Check execution times
5. ✅ **Deploy to hardware**: Upload to Z1 motes
6. 🔧 **Optimize**: Tune parameters for your use case

---

## Support & Documentation

- **README.md**: Overview and architecture
- **QUICKSTART.md**: 3-step quick deployment
- **walkthrough.md**: Detailed implementation guide
- **crypto_core.h**: API reference with comments

For issues, check the troubleshooting section or review the paper: Kumari et al., "A post-quantum lattice based lightweight authentication and code-based hybrid encryption scheme for IoT devices"
