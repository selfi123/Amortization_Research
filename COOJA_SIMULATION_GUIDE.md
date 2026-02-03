# Cooja Simulation Testing Guide
## Session Amortization Implementation

---

## Overview

This guide explains how to test the session amortization implementation using Cooja, the Contiki-NG network simulator. Cooja allows you to simulate IoT networks with multiple nodes and analyze protocol behavior, energy consumption, and performance metrics.

---

## Prerequisites

### 1. Contiki-NG Installation
Ensure you have Contiki-NG installed at:
```
C:/contiki-ng/
```

### 2. Required Tools
- Java Runtime Environment (JRE) - for Cooja GUI
- ARM/MSP430 toolchain - for compiling mote binaries
- Make - for building firmware

### 3. Verify Installation
```bash
cd C:/contiki-ng
ant jar
```
This should build the Cooja simulator JAR file.

---

## Target Platform

### Recommended: Zolertia Z1 Mote

The Z1 mote is ideal for this simulation because:
- ✅ Has sufficient RAM/ROM for post-quantum crypto
- ✅ MSP430 processor (well-supported)
- ✅ 802.15.4 radio simulation
- ✅ Energy profiling capabilities

**Alternative platforms:**
- Sky mote (less RAM, may need optimization)
- Cooja mote (simplified, for protocol testing only)
- Native mote (for quick functional testing)

---

## Step 1: Compile for Z1 Target

### Compile Sender Node
```bash
cd c:/Users/aloob/Desktop/Amortization_Research
make TARGET=z1 node-sender
```

**Expected output:**
```
build/z1/node-sender.z1
```

### Compile Gateway Node
```bash
make TARGET=z1 node-gateway
```

**Expected output:**
```
build/z1/node-gateway.z1
```

### Troubleshooting Compilation Issues

If you encounter errors about missing hardware RNG:
1. The `crypto_secure_random()` function needs `random_rand()` from Contiki
2. For Z1 builds, add this to `crypto_core_session.c`:
```c
#ifdef CONTIKI
#include "dev/random.h"  // Add at top of file
// Then use random_rand() directly (no fallback needed)
#endif
```

If you get memory errors:
- Z1 has 8KB RAM, 92KB ROM
- Post-quantum crypto is RAM-intensive
- May need to reduce constants like `MAX_SESSIONS`, `RING_SIZE`, or `LDPC_ROWS`

---

## Step 2: Create Cooja Simulation File

### Option A: Using Cooja GUI (Recommended)

1. **Start Cooja:**
```bash
cd C:/contiki-ng/tools/cooja
ant run
```

2. **Create New Simulation:**
   - File → New Simulation
   - Name: "Session_Amortization_Test"
   - Select random seed or use default

3. **Add Gateway Mote:**
   - Motes → Add Motes → Create new mote type → Z1 mote
   - Browse to: `c:/Users/aloob/Desktop/Amortization_Research/build/z1/node-gateway.z1`
   - Mote type ID: `gateway`
   - Click "Create"
   - Add 1 mote at position (0, 0, 0)

4. **Add Sender Mote:**
   - Motes → Add Motes → Create new mote type → Z1 mote
   - Browse to: `c:/Users/aloob/Desktop/Amortization_Research/build/z1/node-sender.z1`
   - Mote type ID: `sender`
   - Click "Create"
   - Add 1 mote at position (50, 0, 0)

5. **Configure Radio Medium:**
   - Settings → Set radio medium: **UDGM (Unit Disk Graph Medium)**
   - TX range: 50 meters
   - Interference range: 100 meters
   - Success ratio: 100% (for initial testing)

6. **Add Plugins:**
   - Tools → Radio messages
   - Tools → Mote output (log viewer)
   - Tools → Timeline (for packet visualization)
   - Tools → Collect View (for statistics)
   - **Essential:** Tools → Powertrace (for energy profiling)

7. **Save Simulation:**
   - File → Save Simulation
   - Save as: `session_amortization.csc`

### Option B: Manual CSC File Creation

Create `session_amortization.csc`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <project EXPORT="discard">[APPS_DIR]/mrm</project>
  <project EXPORT="discard">[APPS_DIR]/mspsim</project>
  <project EXPORT="discard">[APPS_DIR]/avrora</project>
  <project EXPORT="discard">[APPS_DIR]/serial_socket</project>
  <project EXPORT="discard">[APPS_DIR]/powertracker</project>
  
  <simulation>
    <title>Session Amortization Test</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      org.contikios.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>gateway</identifier>
      <description>Gateway Node</description>
      <firmware>c:/Users/aloob/Desktop/Amortization_Research/build/z1/node-gateway.z1</firmware>
    </motetype>
    <motetype>
      org.contikios.cooja.mspmote.Z1MoteType
      <identifier>sender</identifier>
      <description>Sender Node</description>
      <firmware>c:/Users/aloob/Desktop/Amortization_Research/build/z1/node-sender.z1</firmware>
    </motetype>
    <mote>
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>0.0</x>
        <y>0.0</y>
        <z>0.0</z>
      </interface_config>
      <motetype_identifier>gateway</motetype_identifier>
    </mote>
    <mote>
      <interface_config>
        org.contikios.cooja.interfaces.Position
        <x>50.0</x>
        <y>0.0</y>
        <z>0.0</z>
      </interface_config>
      <motetype_identifier>sender</motetype_identifier>
    </mote>
  </simulation>
</simconf>
```

---

## Step 3: Run the Simulation

### Start Simulation
1. Open Cooja
2. File → Open Simulation → `session_amortization.csc`
3. Click **Start** button

### What to Expect in Logs

#### Gateway Node Log:
```
=== Post-Quantum Gateway Node Starting ===
[Initialization] Generating cryptographic keys...
Ring-LWE key generation: SUCCESS
LDPC matrix generation: SUCCESS
=== Gateway Ready ===
Listening for incoming connections on UDP port 5678...

[Authentication Phase] Received ring signature + syndrome
Syndrome size: 51 bytes
Verifying ring signature...
*** SIGNATURE VALID ***
Decoding LDPC syndrome to recover error vector...
LDPC decoding successful! Error vector recovered (weight=102)
Generating session parameters...
SID: [a3b4c5d6e7f8a9b0]
Deriving master session key K_master...
K_master derived successfully
Creating session entry in gateway table...
Session created (active sessions: 1/16)
Sending ACK with N_G and SID to sender...
ACK sent! Session established. Waiting for encrypted data...

[Data Phase] Received encrypted message
SID: [a3b4c5d6e7f8a9b0]
Counter: 0
Ciphertext size: 26 bytes
Session found. Decrypting message...
Session decryption successful!
  - K_i derived from K_master
  - AEAD tag verified
  - Counter updated (last_seq=0)

========================================
*** DECRYPTED MESSAGE: Hello IoT #1 ***
========================================

[Data Phase] Received encrypted message
Counter: 1
...
*** DECRYPTED MESSAGE: Hello IoT #2 ***
...
[continues for all 10 messages]
```

#### Sender Node Log:
```
=== Post-Quantum Sender Node Starting ===
[Phase 1] Generating Ring-LWE keys...
Ring-LWE key generation successful

[Phase 2] Starting Ring Signature Authentication...
Initializing LDPC public key (hardcoded/shared)...
Generating LDPC error vector for session authentication...
Error vector generated (weight=102)
Encoding syndrome from error vector...
Syndrome encoded (51 bytes)
Generating ring signature (N=3 members)...
Ring signature generated successfully
Sending authentication packet to gateway...

Authentication ACK received! Gateway authenticated us.
Received Gateway Nonce (N_G) and Session ID (SID)
SID: [a3b4c5d6e7f8a9b0]
Deriving master session key K_master...
Session initialized (counter=0)
K_master derived successfully

Proceeding to encrypted data transmission...
Sending 10 messages using session encryption...

Message 1: 'Hello IoT #1' encrypted (26 bytes ciphertext)
  -> Sent with counter=0 (wire size: 41 bytes)
Message 2: 'Hello IoT #2' encrypted (26 bytes ciphertext)
  -> Sent with counter=1 (wire size: 41 bytes)
...
[continues for all 10 messages]

Data transmission complete! Sent 10 messages.
=== PROTOCOL COMPLETE ===
```

### Success Criteria
✅ Gateway verifies ring signature  
✅ Gateway decodes LDPC syndrome  
✅ Session establishment (SID generated)  
✅ All 10 DATA messages decrypt successfully  
✅ No replay protection errors  
✅ No AEAD tag verification errors

---

## Step 4: Collect Performance Metrics

### Energy Consumption (Powertrace)

Enable Powertrace in your code by adding to both nodes:

```c
// In PROCESS_THREAD, after PROCESS_BEGIN():
#if ENERGEST_CONF_ON
ENERGEST_ON(ENERGEST_TYPE_CPU);
ENERGEST_ON(ENERGEST_TYPE_LPM);
ENERGEST_ON(ENERGEST_TYPE_TRANSMIT);
ENERGEST_ON(ENERGEST_TYPE_LISTEN);
#endif
```

Powertrace will output:
```
Powertrace: P cpu 12345 lpm 54321 tx 1234 rx 5678
```
Where:
- `cpu` = CPU active time (rtimer ticks)
- `lpm` = Low-power mode time
- `tx` = Radio transmit time
- `rx` = Radio listen/receive time

### CPU Time Breakdown

Add timing measurements:

```c
// Before LDPC encode (in sender AUTH phase):
rtimer_clock_t start = RTIMER_NOW();
ldpc_encode(syndrome, &auth_error_vector, &shared_ldpc_pubkey);
rtimer_clock_t ldpc_time = RTIMER_NOW() - start;
LOG_INFO("LDPC encode time: %u rtimer ticks\n", ldpc_time);

// Before session encrypt (in DATA phase):
start = RTIMER_NOW();
session_encrypt(&session_ctx, plaintext, pt_len, ciphertext, &cipher_len);
rtimer_clock_t session_time = RTIMER_NOW() - start;
LOG_INFO("Session encrypt time: %u rtimer ticks\n", session_time);
```

### Expected Performance Improvements

| Metric | Baseline (Per-Message LDPC) | Session Amortization | Improvement |
|--------|----------------------------|---------------------|-------------|
| **CPU time (10 msgs)** | ~11 × LDPC_time | ~1 × LDPC_time + 10 × HKDF_time | **70-80% reduction** |
| **Energy (mJ)** | ~550 mJ | ~110 mJ | **80% reduction** |
| **Latency (ms)** | ~100 ms/msg | ~10 ms/msg | **90% reduction** |
| **Total time (s)** | ~10-15 s | ~2-3 s | **70% faster** |

---

## Step 5: Analyze Results

### Radio Messages Analysis
In Cooja Radio Messages window:
1. Filter by sender mote → Count AUTH, DATA packets
2. Verify: 1 AUTH + 10 DATA = 11 total packets (as expected)
3. Check packet sizes match wire format specs

### Timeline Analysis
1. View Timeline plugin
2. Observe:
   - AUTH phase (sender → gateway)
   - AUTH_ACK phase (gateway → sender)
   - DATA phase (10 messages rapid succession)
3. Measure time between messages (~10ms if delays enabled)

### Collect View Statistics
1. Open Collect View
2. Monitor:
   - Packet delivery ratio (should be 100% for simple 2-node topology)
   - Retransmissions (should be 0 if no packet loss)
   - Latency histograms

---

## Step 6: Comparison with Baseline

To properly evaluate session amortization, you need baseline metrics:

### Create Baseline Simulation

1. **Checkout original code** (before session amortization)
2. **Compile baseline:**
```bash
git checkout <commit-before-amortization>  # if using git
make TARGET=z1 clean
make TARGET=z1 node-sender node-gateway
```
3. **Run same Cooja simulation** with baseline binaries
4. **Capture metrics:** Energy, CPU time, latency

### Comparison Table Template

| Metric | Baseline | Amortized | Improvement |
|--------|----------|-----------|-------------|
| LDPC operations | 11 | 1 | 91% reduction |
| CPU time (total) | ___ ms | ___ ms | ___% |
| Energy (sender) | ___ mJ | ___ mJ | ___% |
| Energy (gateway) | ___ mJ | ___ mJ | ___% |
| Avg latency/msg | ___ ms | ___ ms | ___% |
| Total protocol time | ___ s | ___ s | ___% |

---

## Troubleshooting Common Issues

### Issue 1: Motes Don't Communicate
**Symptoms:** No AUTH_ACK received  
**Solution:**
- Check radio range (should be ≥ distance between motes)
- Verify both motes started successfully
- Check for crashes in Mote Output window
- Ensure UDP port matches (default 5678)

### Issue 2: LDPC Decoding Fails
**Symptoms:** "LDPC decoding failed!" in gateway log  
**Solution:**
- Error vector weight might be too high/low
- LDPC parameters mismatch between sender/gateway
- Verify `shared_ldpc_pubkey` is same on both sides

### Issue 3: Replay Protection Errors
**Symptoms:** "Replay attack detected!" for valid messages  
**Solution:**
- Counter might overflow or restart
- Ensure counter increments correctly
- Check for packet reordering (shouldn't happen in simple topology)

### Issue 4: Memory Overflow
**Symptoms:** Mote crashes, stack overflow  
**Solution:**
- Reduce `MAX_SESSIONS` from 16 to 8 or 4
- Reduce `RING_SIZE` if possible
- Optimize buffer sizes
- Use `-Os` optimization flag

### Issue 5: Energy Values Seem Low
**Symptoms:** Powertrace shows near-zero energy  
**Solution:**
- Ensure `ENERGEST_CONF_ON` is defined
- Check that ENERGEST macros are called
- Use longer simulation time
- Verify Powertrace plugin is active

---

## Advanced: Multi-Sender Simulation

To test session management with multiple senders:

1. **Add more sender motes** (e.g., 3-5 senders)
2. **Stagger start times** (each sender delays 5-10 seconds)
3. **Observe gateway session table:**
   - Should create separate sessions for each sender
   - LRU eviction if > MAX_SESSIONS
4. **Check for session ID collisions** (very unlikely with 8-byte random SID)

---

## Expected Simulation Duration

- **Minimal test:** ~30 seconds (1 sender, 10 messages)
- **Full protocol:** ~60 seconds (includes initialization)
- **Multi-sender:** ~120 seconds (3 senders × 10 messages each)
- **Energy profiling:** ~300 seconds (for stable measurements)

---

## Deliverables After Testing

### 1. Simulation Logs
Save complete logs:
- File → Save simulation output
- Save as: `simulation_output.txt`

### 2. Energy Profile
Export Powertrace data:
- Tools → Powertrace → Export CSV
- Save as: `energy_profile.csv`

### 3. Screenshots
Capture:
- Timeline view showing message sequence
- Radio messages window
- Final mote output logs
- Energy consumption graph (if available)

### 4. Performance Report
Create `SIMULATION_RESULTS.md` with:
- Metrics comparison table
- Energy graphs
- Key observations
- Success/failure analysis

---

## Summary

**Quick Start:**
```bash
# 1. Compile for Z1
make TARGET=z1 node-sender node-gateway

# 2. Start Cooja
cd C:/contiki-ng/tools/cooja
ant run

# 3. Create simulation (GUI or CSC file)
# 4. Add plugins (Radio Messages, Mote Output, Powertrace)
# 5. Run simulation
# 6. Analyze logs and metrics
```

**Success Indicators:**
- ✅ Both motes start successfully
- ✅ LDPC encode/decode succeed
- ✅ Session established (SID logged)
- ✅ All 10 messages decrypt correctly
- ✅ ~90% LDPC operation reduction
- ✅ ~70-80% energy savings

**Next Steps After Validation:**
- Scale to 5-10 sender nodes
- Test under packet loss (reduce success ratio)
- Measure real-world performance on hardware
- Compare with other IoT security schemes
